#define _XOPEN_SOURCE 700 // Necesare pentru diverse functii POSIX
#define _DEFAULT_SOURCE   // Pentru ctime, strsignal etc.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h> // Pentru waitpid()
#include <signal.h>   // Pentru kill(), sigaction(), semnale
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <dirent.h>   // Pentru opendir, readdir, closedir
#include <ctype.h>    // Pentru isspace

// --- Constante (reutilizate) ---
#define MAX_USERNAME_LEN 50
#define MAX_CLUE_LEN 256
#define MAX_INPUT_BUFFER 512
#define MAX_PATH_LEN PATH_MAX
#define TREASURE_FILE_NAME "treasures.bin"
#define DIR_PERMS 0755
#define FILE_PERMS 0644

#define COMMAND_FILE "monitor_command.tmp" // Nume fisier comunicare

// --- Structuri de date (reutilizate) ---
typedef struct {
    float latitude;
    float longitude;
} GPSCoordinates;

typedef struct {
    int id;
    char username[MAX_USERNAME_LEN];
    GPSCoordinates coordinates;
    char clue[MAX_CLUE_LEN];
    int value;
} Treasure;

// --- Variabile Globale pentru Starea Hub-ului ---
volatile sig_atomic_t monitor_is_running = 0; // Flag: monitorul ruleaza?
volatile sig_atomic_t waiting_for_monitor_stop = 0; // Flag: hub asteapta oprirea monitorului?
pid_t monitor_pid = 0; // PID-ul procesului monitor

// --- Flag-uri de Semnal pentru Monitor ---
volatile sig_atomic_t sigusr1_received = 0; // Primire SIGUSR1 (list_hunts)
volatile sig_atomic_t sigusr2_received = 0; // Primire SIGUSR2 (list_treasures/view_treasure)
volatile sig_atomic_t sigterm_received = 0; // Primire SIGTERM (stop)

// --- Declaratii Anticipate ---
void monitor_main_loop();
void monitor_list_hunts();
void monitor_list_all_treasures();
int count_treasures_in_hunt(const char *hunt_id);
void list_treasures_for_hunt(const char *hunt_id);
void print_treasure_details(const Treasure *t); // Functie helper pt afisare comoara

// --- Signal Handlers ---

// Handler-ele simple ale Monitorului (doar seteaza flag-uri)
void monitor_sigusr1_handler(int signum) { (void)signum; sigusr1_received = 1; }
void monitor_sigusr2_handler(int signum) { (void)signum; sigusr2_received = 1; }
void monitor_sigterm_handler(int signum) { (void)signum; sigterm_received = 1; }

// Handler-ul SIGCHLD al Hub-ului (gestioneaza terminarea copilului)
void hub_sigchld_handler(int signum) {
    (void)signum;
    int status;
    pid_t terminated_pid;
    // Bucla pentru a gestiona toti copiii terminati (desi avem doar unul)
    while ((terminated_pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (terminated_pid == monitor_pid) { // Verifica daca e monitorul nostru
            printf("\n[Hub] Procesul monitor (PID %d) s-a terminat.\n", terminated_pid);
            // Afiseaza statusul de terminare
            if (WIFEXITED(status)) {
                printf("[Hub] Monitorul a iesit normal cu status %d.\n", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("[Hub] Monitorul a fost terminat de semnalul %d (%s).\n", WTERMSIG(status), strsignal(WTERMSIG(status)));
            } else {
                printf("[Hub] Monitorul s-a terminat cu un status neobisnuit: %d.\n", status);
            }
            // Reseteaza starea hub-ului
            monitor_pid = 0;
            monitor_is_running = 0;
            waiting_for_monitor_stop = 0;
            printf("> "); // Re-afiseaza prompt-ul
            fflush(stdout);
        }
    }
}

// --- Functie Ajutatoare pentru Sigaction ---
int setup_signal_handler(int signum, void (*handler)(int)) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART; // Important pentru a reporni apelurile de sistem intrerupte
    if (sigaction(signum, &sa, NULL) == -1) {
        char msg[100];
        snprintf(msg, sizeof(msg), "Eroare la configurarea sigaction pentru semnalul %d", signum);
        perror(msg);
        return -1;
    }
    return 0;
}

// --- Functiile Procesului Monitor ---


void process_monitor_command_file() {
    printf("[Monitor %d] Procesez fisierul de comanda...\n", getpid());
    FILE *fp_cmd = fopen(COMMAND_FILE, "r");
    if (!fp_cmd) {
        // Nu e neaparat o eroare fatala, poate hub-ul nu a apucat sa scrie
        fprintf(stderr, "[Monitor %d] Avertisment: Nu pot deschide %s pentru citire.\n", COMMAND_FILE);
        // Ca fallback, ar putea lista tot, sau sa nu faca nimic
        monitor_list_all_treasures(); // Sau un mesaj de eroare
        return;
    }

    char line_buffer[MAX_INPUT_BUFFER];
    char command_type[100];
    char hunt_id_arg[MAX_PATH_LEN];
    char treasure_id_str_arg[100]; // Ca string initial

    // Citeste tipul comenzii
    if (fgets(command_type, sizeof(command_type), fp_cmd) == NULL) {
        fprintf(stderr, "[Monitor %d] Eroare: Fisier comanda gol sau format invalid (tip comanda).\n", getpid());
        fclose(fp_cmd);
        unlink(COMMAND_FILE); // Sterge fisierul dupa procesare/eroare
        return;
    }
    command_type[strcspn(command_type, "\n")] = 0; // Elimina newline

    if (strcmp(command_type, "list_treasures") == 0) {
        // Citeste hunt_id
        if (fgets(hunt_id_arg, sizeof(hunt_id_arg), fp_cmd) == NULL) {
            fprintf(stderr, "[Monitor %d] Eroare: Format invalid pentru list_treasures (lipsa hunt_id).\n", getpid());
        } else {
            hunt_id_arg[strcspn(hunt_id_arg, "\n")] = 0;
            printf("[Monitor %d] Actiune: list_treasures pentru hunt '%s'.\n", getpid(), hunt_id_arg);
            list_treasures_for_hunt(hunt_id_arg); // Functia existenta
        }
    } else if (strcmp(command_type, "view_treasure") == 0) {
        // Citeste hunt_id
        if (fgets(hunt_id_arg, sizeof(hunt_id_arg), fp_cmd) == NULL ||
            fgets(treasure_id_str_arg, sizeof(treasure_id_str_arg), fp_cmd) == NULL) { // Citeste treasure_id
            fprintf(stderr, "[Monitor %d] Eroare: Format invalid pentru view_treasure (lipsa argumente).\n", getpid());
        } else {
            hunt_id_arg[strcspn(hunt_id_arg, "\n")] = 0;
            treasure_id_str_arg[strcspn(treasure_id_str_arg, "\n")] = 0;

            // Convertim treasure_id_str_arg in int
            long treasure_id_val_long;
            char *endptr;
            errno = 0;
            treasure_id_val_long = strtol(treasure_id_str_arg, &endptr, 10);
            if (errno != 0 || endptr == treasure_id_str_arg || (*endptr != '\0' && !isspace(*endptr)) || treasure_id_val_long <= 0 || treasure_id_val_long > INT_MAX) {
                 fprintf(stderr, "[Monitor %d] Eroare: treasure_id '%s' invalid din fisierul de comanda.\n", getpid(), treasure_id_str_arg);
            } else {
                int treasure_id_val = (int)treasure_id_val_long;
                printf("[Monitor %d] Actiune: view_treasure pentru hunt '%s', comoara ID %d.\n", getpid(), hunt_id_arg, treasure_id_val);
                // Aici ar trebui o functie noua, ex:
                // monitor_view_specific_treasure(hunt_id_arg, treasure_id_val);
                // Pentru simplificare, putem refolosi list_treasures_for_hunt si utilizatorul
                // ar trebui sa caute vizual comoara specifica. Sau putem implementa cautarea.
                // Ca exemplu, afisam doar un mesaj:
                printf("    (Simulare vizualizare comoara %d din hunt %s. Ar trebui implementata cautarea efectiva.)\n", treasure_id_val, hunt_id_arg);
                // Daca vrei sa vezi daca exista:
                // if (check_treasure_exists_in_hunt(hunt_id_arg, treasure_id_val)) { ... afiseaza ... }
                // Pentru a afisa efectiv, monitorul ar trebui sa aiba si o functie similara cu `handle_view` din Faza 1.
            }
        }
    } else {
        fprintf(stderr, "[Monitor %d] Eroare: Tip comanda necunoscut '%s' in fisierul de comanda.\n", getpid(), command_type);
    }

    fclose(fp_cmd);
    unlink(COMMAND_FILE); // Sterge fisierul de comanda dupa procesare
}

// Bucla principala a monitorului: asteapta si reactioneaza la semnale
void monitor_main_loop() {
    printf("[Monitor %d] Pornit si asteapta semnale...\n", getpid());

    // Configureaza handler-ele de semnal
    if (setup_signal_handler(SIGUSR1, monitor_sigusr1_handler) == -1 ||
        setup_signal_handler(SIGUSR2, monitor_sigusr2_handler) == -1 ||
        setup_signal_handler(SIGTERM, monitor_sigterm_handler) == -1) {
        fprintf(stderr, "[Monitor %d] Eroare fatala la configurarea handler-elor de semnal. Iesire.\n", getpid());
        exit(EXIT_FAILURE);
    }

    // Bucla pana la primirea SIGTERM
    while (!sigterm_received) {
        // Verifica flag-urile setate de handlere
        if (sigusr1_received) {
            sigusr1_received = 0; // Reseteaza flag-ul
            printf("[Monitor %d] Primit SIGUSR1: Cerere listare hunt-uri.\n", getpid());
            monitor_list_hunts(); // Executa actiunea
        }
        if (sigusr2_received) {
            sigusr2_received = 0; // Reseteaza flag-ul
            printf("[Monitor %d] Primit SIGUSR2: Cerere listare/vizualizare comori (execut listare completa).\n", getpid());
            process_monitor_command_file(); // Proceseaza comanda detaliata din fisier
            //monitor_list_all_treasures(); // Executa actiunea generica
        }

        // Asteapta eficient urmatorul semnal
        pause();
    }

    // Iesire din bucla (SIGTERM primit)
    printf("[Monitor %d] SIGTERM primit. Curatenie si iesire...\n", getpid());
    printf("[Monitor %d] Execut task-uri finale (intarziere %d secunde)...\n", getpid(), 2);
    sleep(2); // Intarziere ceruta
    printf("[Monitor %d] Iesire acum.\n", getpid());
    exit(EXIT_SUCCESS); // Iesire normala
}

// Monitor: Numara comorile dintr-un hunt (helper)
int count_treasures_in_hunt(const char *hunt_id) {
    char treasure_file_path[MAX_PATH_LEN];
    snprintf(treasure_file_path, sizeof(treasure_file_path), "./%s/%s", hunt_id, TREASURE_FILE_NAME);
    int fd = open(treasure_file_path, O_RDONLY);
    if (fd == -1) return 0; // Daca nu se poate deschide, 0 comori

    int count = 0;
    Treasure t;
    // Citeste inregistrari complete
    while (read(fd, &t, sizeof(Treasure)) == sizeof(Treasure)) {
        count++;
    }
    close(fd);
    return count;
}

// Monitor: Listeaza hunt-urile si numarul de comori (activat de SIGUSR1)
void monitor_list_hunts() {
    printf("\n--- [Monitor] Hunt-uri Descoperite ---\n");
    DIR *dirp = opendir(".");
    if (!dirp) {
        perror("[Monitor] Eroare la deschiderea directorului curent (.)");
        printf("-------------------------------------\n");
        return;
    }

    struct dirent *entry;
    struct stat st;
    int hunt_count = 0;
    char path_buffer[MAX_PATH_LEN]; // Buffer pentru a construi cai

    while ((entry = readdir(dirp)) != NULL) {
        // Construieste calea completa pentru stat()
        snprintf(path_buffer, sizeof(path_buffer), "./%s", entry->d_name);
        if (stat(path_buffer, &st) == 0) {
            // Verifica daca e director, nu e . sau ..
            if (S_ISDIR(st.st_mode) && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                // Verifica daca contine treasures.bin (criteriu pentru hunt valid)
                snprintf(path_buffer, sizeof(path_buffer), "./%s/%s", entry->d_name, TREASURE_FILE_NAME);
                struct stat treasure_stat;
                 if (stat(path_buffer, &treasure_stat) == 0 && S_ISREG(treasure_stat.st_mode)) {
                     int treasure_count = count_treasures_in_hunt(entry->d_name);
                     printf("  Hunt ID: %-20s (%d comori)\n", entry->d_name, treasure_count); // Aliniere simpla
                     hunt_count++;
                 }
            }
        }
        // Ignora erorile stat() sau intrarile care nu sunt directoare/hunt-uri valide
    }
    closedir(dirp);

    if (hunt_count == 0) {
        printf("  (Niciun hunt valid gasit)\n");
    }
    printf("-------------------------------------\n");
    fflush(stdout); // Asigura afisarea
}

// Helper: Afiseaza detaliile unei comori (similar cu Faza 1)
void print_treasure_details(const Treasure *t) {
    if (!t) return;
    printf("    ID:          %d\n", t->id);
    printf("    Utilizator:  %s\n", t->username);
    printf("    GPS (Lat,Lon): (%.6f, %.6f)\n", t->coordinates.latitude, t->coordinates.longitude);
    printf("    Indiciu:     \"%s\"\n", t->clue);
    printf("    Valoare:     %d\n", t->value);
    printf("    ----\n");
}

// Monitor: Listeaza comorile dintr-un hunt specific (helper)
void list_treasures_for_hunt(const char *hunt_id) {
    char treasure_file_path[MAX_PATH_LEN];
    snprintf(treasure_file_path, sizeof(treasure_file_path), "./%s/%s", hunt_id, TREASURE_FILE_NAME);

    int fd = open(treasure_file_path, O_RDONLY);
    if (fd == -1) {
         // Nu raportam eroare daca fisierul pur si simplu nu exista
         if (errno != ENOENT) {
             fprintf(stderr, "[Monitor] Avertisment: Nu pot deschide %s pentru hunt '%s': %s\n",
                     TREASURE_FILE_NAME, hunt_id, strerror(errno));
         }
         return;
    }

    printf("--- [Monitor] Comori in Hunt: %s ---\n", hunt_id);
    Treasure current_treasure;
    ssize_t bytes_read;
    int count = 0;

    while ((bytes_read = read(fd, &current_treasure,sizeof(Treasure))) > 0) {
        if (bytes_read < sizeof(Treasure)) {
            fprintf(stderr, "[Monitor] Avertisment: Fisierul '%s' pare corupt (citire partiala).\n", treasure_file_path);
            break;
        }
        count++;
        print_treasure_details(&current_treasure); // Afiseaza detaliile
    }

    if (bytes_read < 0) {
        fprintf(stderr, "[Monitor] Eroare la citirea fisierului '%s': %s\n", treasure_file_path, strerror(errno));
    }
    if (count == 0) {
        printf("    (Nicio comoara gasita in acest hunt)\n");
        printf("    ----\n");
    }
    close(fd);
}

// Monitor: Listeaza TOATE comorile din TOATE hunt-urile (activat de SIGUSR2)
void monitor_list_all_treasures() {
     printf("\n--- [Monitor] Listare Toate Comorile (Actiune SIGUSR2) ---\n");
     DIR *dirp = opendir(".");
     if (!dirp) {
         perror("[Monitor] Eroare la deschiderea directorului curent (.)");
         printf("--------------------------------------------------------\n");
         return;
     }

     struct dirent *entry;
     struct stat st;
     int hunts_processed = 0;
     char path_buffer[MAX_PATH_LEN];

     // Parcurge directorul curent
     while ((entry = readdir(dirp)) != NULL) {
         snprintf(path_buffer, sizeof(path_buffer), "./%s", entry->d_name);
         if (stat(path_buffer, &st) == 0) {
             // Daca e director, nu . sau ..
             if (S_ISDIR(st.st_mode) && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                 // Verifica daca e hunt valid (contine treasures.bin)
                 snprintf(path_buffer, sizeof(path_buffer), "./%s/%s", entry->d_name, TREASURE_FILE_NAME);
                 struct stat treasure_stat;
                 if (stat(path_buffer, &treasure_stat) == 0 && S_ISREG(treasure_stat.st_mode)) {
                     // Daca e valid, listeaza comorile din el
                     list_treasures_for_hunt(entry->d_name);
                     hunts_processed++;
                 }
             }
         }
     }
     closedir(dirp);

     if (hunts_processed == 0) {
         printf("  (Niciun hunt valid gasit pentru a lista comori)\n");
     }
     printf("--------------------------------------------------------\n");
     fflush(stdout); // Asigura afisarea
}


// --- Functia Principala a Treasure Hub ---
int main() {
    char command_buffer[MAX_INPUT_BUFFER]; // Buffer pentru comanda
    char *cmd_token; // Pointer la comanda (primul cuvant)
    char *arg1 = NULL; // Pointer la primul argument (hunt_id)
    char *arg2 = NULL; // Pointer la al doilea argument (treasure_id)

    printf("Interfata Treasure Hub. Introduceti 'help' pentru comenzi.\n");

    // Configureaza handler SIGCHLD pentru hub
    if (setup_signal_handler(SIGCHLD, hub_sigchld_handler) == -1) {
        return EXIT_FAILURE;
    }

    // Bucla principala
    while (1) {
        // Verifica daca asteptam monitorul
        if (waiting_for_monitor_stop) {
            printf("[Hub] Astept terminarea monitorului... (comenzi blocate)\n");
            // Bucla de asteptare activa (SIGCHLD va reseta flag-ul)
             while(waiting_for_monitor_stop) {
                 pause(); // Asteapta orice semnal (inclusiv SIGCHLD)
             }
             // Dupa ce SIGCHLD a rulat, prompt-ul e reafisat de handler
            continue; // Revino la inceputul buclei principale
        }

        printf("> "); // Afiseaza prompt
        fflush(stdout);

        // Citeste comanda
        if (fgets(command_buffer, sizeof(command_buffer), stdin) == NULL) {
            if (feof(stdin)) { // Ctrl+D
                printf("\n[Hub] EOF detectat. Iesire.\n");
                if (monitor_is_running) {
                    // Oprim fortat monitorul la iesirea hub-ului daca inca ruleaza
                    printf("[Hub] Trimit SIGTERM monitorului (PID %d) la iesire.\n", monitor_pid);
                    kill(monitor_pid, SIGTERM);
                    // Aici nu mai asteptam, hub-ul se termina
                }
                break; // Iesi din bucla while
            } else {
                perror("[Hub] Eroare la citirea comenzii");
                continue;
            }
        }

        // Elimina newline
        command_buffer[strcspn(command_buffer, "\n")] = 0;

        // --- Parsare Comanda si Argumente ---
        cmd_token = strtok(command_buffer, " \t\n"); // Extrage comanda
        if (cmd_token == NULL) continue; // Linie goala

        arg1 = strtok(NULL, " \t\n"); // Extrage primul argument (poate fi NULL)
        arg2 = strtok(NULL, " \t\n"); // Extrage al doilea argument (poate fi NULL)
        // strtok(NULL, ...) continua de unde a ramas anterior

        // --- Procesare Comenzi ---
        if (strcmp(cmd_token, "start_monitor") == 0) {
            if (arg1 != NULL) { // Comanda nu asteapta argumente
                 fprintf(stderr, "[Hub] Eroare: Comanda 'start_monitor' nu necesita argumente.\n");
                 continue;
            }
            if (monitor_is_running) {
                fprintf(stderr, "[Hub] Eroare: Monitorul deja ruleaza (PID %d).\n", monitor_pid);
            } else {
                monitor_pid = fork(); // Creeaza copilul
                if (monitor_pid < 0) { /* Eroare fork */ }
                else if (monitor_pid == 0) { // Proces copil (Monitor)
                    signal(SIGCHLD, SIG_DFL); // Reseteaza handler SIGCHLD
                    monitor_main_loop();      // Porneste logica monitorului
                    exit(EXIT_SUCCESS);       // Iesire normala copil
                } else { // Proces parinte (Hub)
                    monitor_is_running = 1;
                    printf("[Hub] Proces monitor pornit cu PID %d.\n", monitor_pid);
                }
            }
        } else if (strcmp(cmd_token, "stop_monitor") == 0) {
            if (arg1 != NULL) {
                 fprintf(stderr, "[Hub] Eroare: Comanda 'stop_monitor' nu necesita argumente.\n");
                 continue;
            }
            if (!monitor_is_running) {
                fprintf(stderr, "[Hub] Eroare: Monitorul nu ruleaza.\n");
            } else {
                printf("[Hub] Trimit SIGTERM monitorului (PID %d).\n", monitor_pid);
                if (kill(monitor_pid, SIGTERM) == -1) {
                    perror("[Hub] Eroare la trimiterea SIGTERM");
                    // Resetare fortata a starii daca kill esueaza
                    monitor_is_running = 0; monitor_pid = 0;
                } else {
                    waiting_for_monitor_stop = 1; // Activeaza starea de asteptare
                    printf("[Hub] Astept terminarea monitorului... (comenzi blocate)\n");
                    // SIGCHLD handler va prelua de aici
                }
            }
        } else if (strcmp(cmd_token, "list_hunts") == 0) {
             if (arg1 != NULL) {
                 fprintf(stderr, "[Hub] Eroare: Comanda 'list_hunts' nu necesita argumente.\n");
                 continue;
             }
            if (!monitor_is_running) {
                fprintf(stderr, "[Hub] Eroare: Monitorul nu ruleaza.\n");
            } else {
                printf("[Hub] Trimit cerere catre monitor: list_hunts (SIGUSR1)\n");
                if (kill(monitor_pid, SIGUSR1) == -1) {
                    perror("[Hub] Eroare la trimiterea SIGUSR1");
                }
                // Hub-ul nu asteapta aici, monitorul va afisa rezultatul asincron
            }
        } 
        
        else if (strcmp(cmd_token, "list_treasures") == 0) {
            if (arg1 == NULL || arg2 != NULL) {
                fprintf(stderr, "[Hub] Utilizare: list_treasures <hunt_id>\n");
                continue;
            }
            if (!monitor_is_running) { /* ... eroare ... */ }
            else {
                FILE *fp_cmd = fopen(COMMAND_FILE, "w"); // Deschide pentru scriere (suprascrie)
                if (!fp_cmd) {
                    perror("[Hub] Eroare la deschiderea fisierului de comanda");
                } else {
                    fprintf(fp_cmd, "list_treasures\n%s\n", arg1); // Scrie comanda si hunt_id
                    fclose(fp_cmd);
                    printf("[Hub] Trimit cerere catre monitor: list_treasures pentru '%s' (SIGUSR2)\n", arg1);
                    if (kill(monitor_pid, SIGUSR2) == -1) {
                        perror("[Hub] Eroare la trimiterea SIGUSR2");
                    }
                }
            }
        }
        else if (strcmp(cmd_token, "view_treasure") == 0) {
            if (arg1 == NULL || arg2 == NULL) {
                fprintf(stderr, "[Hub] Utilizare: view_treasure <hunt_id> <treasure_id>\n");
                continue;
            }
            // Ar trebui sa validam si arg2 (treasure_id) ca numar aici
            long treasure_id_val_long;
            char *endptr;
            errno = 0;
            treasure_id_val_long = strtol(arg2, &endptr, 10);
            if (errno != 0 || endptr == arg2 || (*endptr != '\0' && !isspace(*endptr)) || treasure_id_val_long <= 0 || treasure_id_val_long > INT_MAX) {
                fprintf(stderr, "[Hub] Eroare: treasure_id invalid '%s'. Trebuie sa fie un numar intreg pozitiv.\n", arg2);
                continue;
            }
            // int treasure_id_val = (int)treasure_id_val_long; // Nu e nevoie sa o stocam aici
        
            if (!monitor_is_running) { /* ... eroare ... */ }
            else {
                FILE *fp_cmd = fopen(COMMAND_FILE, "w");
                if (!fp_cmd) {
                    perror("[Hub] Eroare la deschiderea fisierului de comanda");
                } else {
                    fprintf(fp_cmd, "view_treasure\n%s\n%s\n", arg1, arg2); // Scrie comanda, hunt_id, treasure_id
                    fclose(fp_cmd);
                    printf("[Hub] Trimit cerere catre monitor: view_treasure pentru %s:%s (SIGUSR2)\n", arg1, arg2);
                    if (kill(monitor_pid, SIGUSR2) == -1) {
                        perror("[Hub] Eroare la trimiterea SIGUSR2");
                    }
                }
            }
        }//aici 


         else if (strcmp(cmd_token, "exit") == 0) {
            if (arg1 != NULL) {
                 fprintf(stderr, "[Hub] Eroare: Comanda 'exit' nu necesita argumente.\n");
                 continue;
            }
            if (monitor_is_running) {
                fprintf(stderr, "[Hub] Eroare: Monitorul (PID %d) inca ruleaza. Folositi 'stop_monitor' intai.\n", monitor_pid);
            } else {
                printf("[Hub] Iesire.\n");
                break; // Iesi din bucla while
            }
        } else if (strcmp(cmd_token, "help") == 0) {
             if (arg1 != NULL) {
                 fprintf(stderr, "[Hub] Eroare: Comanda 'help' nu necesita argumente.\n");
                 continue;
             }
            // Afiseaza textul de ajutor
            printf("Comenzi disponibile:\n");
            printf("  start_monitor                - Porneste procesul monitor.\n");
            printf("  list_hunts                   - Cere monitorului sa listeze hunt-urile.\n");
            printf("  list_treasures <hunt_id>     - Cere monitorului sa listeze comori (afiseaza toate).\n");
            printf("  view_treasure <h_id> <t_id>  - Cere monitorului sa vada o comoara (afiseaza toate).\n");
            printf("  stop_monitor                 - Opreste monitorul si asteapta terminarea.\n");
            printf("  exit                         - Iese din hub (doar daca monitorul e oprit).\n");
            printf("  help                         - Afiseaza acest mesaj.\n");
        } else { // Comanda necunoscuta
            fprintf(stderr, "[Hub] Eroare: Comanda necunoscuta '%s'. Introduceti 'help'.\n", cmd_token);
        }
    } // Sfarsit bucla while(1)

    printf("[Hub] Program terminat.\n");
    return EXIT_SUCCESS;
}