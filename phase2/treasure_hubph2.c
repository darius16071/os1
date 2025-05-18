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

// --- Constante
#define MAX_USERNAME_LEN 50
#define MAX_CLUE_LEN 256
#define MAX_INPUT_BUFFER 512
#define MAX_PATH_LEN PATH_MAX
#define TREASURE_FILE_NAME "treasures.bin"
#define DIR_PERMS 0755
#define FILE_PERMS 0644

#define COMMAND_FILE "monitor_command.tmp" // Nume fisier comunicare


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
//void monitor_list_all_treasures(); 
int count_treasures_in_hunt(const char *hunt_id);
void list_treasures_for_hunt(const char *hunt_id);
void print_treasure_details(const Treasure *t); // Functie helper pt afisare comoara
void process_monitor_command_file();


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
    printf("[Monitor %d] Procesez fisierul de comanda '%s'...\n", getpid(), COMMAND_FILE);
    FILE *fp_cmd = fopen(COMMAND_FILE, "r");
    if (!fp_cmd) {
        fprintf(stderr, "[Monitor %d] Avertisment: Nu pot deschide %s pentru citire.\n", getpid(), COMMAND_FILE);
       
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

            // Validam treasure_id_str_arg ca numar intreg pozitiv
            long treasure_id_val_long;
            char *endptr;
            errno = 0;
            treasure_id_val_long = strtol(treasure_id_str_arg, &endptr, 10);
            if (errno != 0 || endptr == treasure_id_str_arg || (*endptr != '\0' && !isspace(*endptr)) || treasure_id_val_long <= 0 || treasure_id_val_long > INT_MAX) {
                 fprintf(stderr, "[Monitor %d] Eroare: treasure_id '%s' invalid din fisierul de comanda.\n", getpid(), treasure_id_str_arg);
            } else {
                printf("[Monitor %d] Actiune: Delegare view_treasure pentru hunt '%s', comoara ID %s la treasure_manager.\n", getpid(), hunt_id_arg, treasure_id_str_arg);
                fflush(stdout);

                pid_t viewer_pid = fork();
                if (viewer_pid < 0) {
                    perror("[Monitor] Eroare la fork pentru executia treasure_manager");
                } else if (viewer_pid == 0) {
                    // Proces copil (viewer grandchild) - va executa treasure_manager
                    // printf("[Monitor Child - Viewer %d] Executare: ./treasure_manager view %s %s\n", getpid(), hunt_id_arg, treasure_id_str_arg);
                    // fflush(stdout); // Output-ul treasure_manager 

                    
                    execlp("./treasure_manager", "treasure_manager", "view", hunt_id_arg, treasure_id_str_arg, (char *)NULL);
                    
                    // Daca execlp returneaza, a aparut o eroare
                    perror("[Monitor Child - Viewer] Eroare la execlp treasure_manager");
                    exit(EXIT_FAILURE); // Iesire din copil in caz de eroare exec
                } else {
                    // Proces parinte (monitor) - asteapta terminarea treasure_manager
                    int viewer_status;
                    // printf("[Monitor %d] Asteptare finalizare treasure_manager (PID %d)...\n", getpid(), viewer_pid);
                    // fflush(stdout); // Comentat pentru a reduce zgomotul, output-ul treasure_manager e principal
                    waitpid(viewer_pid, &viewer_status, 0); // Asteapta copilul viewer
                    
                    if (WIFEXITED(viewer_status)) {
                        // Nu mai afisam nimic aici, statusul lui treasure_manager nu e relevant pentru utilizatorul hub-ului
                        // printf("[Monitor %d] treasure_manager (PID %d) a terminat cu statusul %d.\n", getpid(), viewer_pid, WEXITSTATUS(viewer_status));
                    } else if (WIFSIGNALED(viewer_status)) {
                        fprintf(stderr, "[Monitor %d] treasure_manager (PID %d) a fost terminat de semnalul %d.\n", getpid(), viewer_pid, WTERMSIG(viewer_status));
                    }
                    fflush(stdout); // Asigura ca orice output anterior al monitorului e afisat
                    fflush(stderr);
                }
            }
        }
    } else {
        fprintf(stderr, "[Monitor %d] Eroare: Tip comanda necunoscut '%s' in fisierul de comanda.\n", getpid(), command_type);
    }

    fclose(fp_cmd);
    if (unlink(COMMAND_FILE) == -1 && errno != ENOENT) { // Sterge fisierul de comanda dupa procesare
        perror("[Monitor] Avertisment: Nu s-a putut sterge fisierul de comanda");
    }
}

// Bucla principala a monitorului: asteapta si reactioneaza la semnale
void monitor_main_loop() {
    printf("[Monitor %d] Pornit si asteapta semnale...\n", getpid());
    fflush(stdout);

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
            printf("\n[Monitor %d] Primit SIGUSR1: Cerere listare hunt-uri.\n", getpid());
            fflush(stdout);
            monitor_list_hunts(); // Executa actiunea
        }
        if (sigusr2_received) {
            sigusr2_received = 0; // Reseteaza flag-ul
            printf("\n[Monitor %d] Primit SIGUSR2: Procesare comanda din '%s'.\n", getpid(), COMMAND_FILE);
            fflush(stdout);
            process_monitor_command_file(); 
        }

        // Asteapta urmatorul semnal
        pause();
    }

    // Iesire din bucla (SIGTERM primit)
    printf("[Monitor %d] SIGTERM primit. Curatenie si iesire...\n", getpid());
    printf("[Monitor %d] Execut task-uri finale (intarziere %d secunde)...\n", getpid(), 2);
    fflush(stdout);
    sleep(2); // Intarziere ceruta
    printf("[Monitor %d] Iesire acum.\n", getpid());
    fflush(stdout);
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
    printf("--- [Monitor] Hunt-uri Descoperite ---\n");
    DIR *dirp = opendir(".");
    if (!dirp) {
        perror("[Monitor] Eroare la deschiderea directorului curent (.)");
        printf("-------------------------------------\n");
        fflush(stdout);
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
                // Acest criteriu e important pentru a nu lista orice director
                char treasure_bin_path[MAX_PATH_LEN];
                snprintf(treasure_bin_path, sizeof(treasure_bin_path), "./%s/%s", entry->d_name, TREASURE_FILE_NAME);
                struct stat treasure_stat_check;
                 if (stat(treasure_bin_path, &treasure_stat_check) == 0 && S_ISREG(treasure_stat_check.st_mode)) {
                     int treasure_count = count_treasures_in_hunt(entry->d_name);
                     printf("  Hunt ID: %-20s (%d comori)\n", entry->d_name, treasure_count); // Aliniere simpla
                     hunt_count++;
                 }
            }
        }
    }
    closedir(dirp);

    if (hunt_count == 0) {
        printf("  (Niciun hunt valid gasit)\n");
    }
    printf("-------------------------------------\n");
    fflush(stdout); // Asigura afisarea
}

// Helper: Afiseaza detaliile unei comori (folosit de list_treasures_for_hunt)
void print_treasure_details(const Treasure *t) {
    if (!t) return;
    printf("    ID:          %d\n", t->id);
    printf("    Utilizator:  %s\n", t->username);
    printf("    GPS (Lat,Lon): (%.6f, %.6f)\n", t->coordinates.latitude, t->coordinates.longitude);
    printf("    Indiciu:     \"%s\"\n", t->clue);
    printf("    Valoare:     %d\n", t->value);
    printf("    ----\n");
}

// Monitor: Listeaza comorile dintr-un hunt specific (folosit de `list_treasures` via command file)
void list_treasures_for_hunt(const char *hunt_id) {
    char treasure_file_path[MAX_PATH_LEN];
    snprintf(treasure_file_path, sizeof(treasure_file_path), "./%s/%s", hunt_id, TREASURE_FILE_NAME);

    // Adaugam verificarea existentei directorului hunt
    struct stat hunt_st;
    char hunt_dir_path[MAX_PATH_LEN];
    snprintf(hunt_dir_path, sizeof(hunt_dir_path), "./%s", hunt_id);
    if (stat(hunt_dir_path, &hunt_st) == -1 || !S_ISDIR(hunt_st.st_mode)) {
        fprintf(stderr, "[Monitor] Eroare: Hunt ID '%s' nu este un director valid sau nu exista.\n", hunt_id);
        fflush(stderr);
        return;
    }

    int fd = open(treasure_file_path, O_RDONLY);
    if (fd == -1) {
         if (errno == ENOENT) {
             printf("--- [Monitor] Comori in Hunt: %s ---\n", hunt_id);
             printf("    (Niciun fisier de comori '%s' gasit in acest hunt sau hunt-ul este gol)\n", TREASURE_FILE_NAME);
             printf("    ----\n");
         } else {
             fprintf(stderr, "[Monitor] Avertisment: Nu pot deschide %s pentru hunt '%s': %s\n",
                     TREASURE_FILE_NAME, hunt_id, strerror(errno));
         }
         fflush(stdout);
         fflush(stderr);
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
        // Mesaj afisat deja daca fisierul nu exista. Daca exista dar e gol:
        struct stat file_st_check;
        if (stat(treasure_file_path, &file_st_check) == 0 && file_st_check.st_size == 0) {
             printf("    (Fisierul de comori este gol)\n");
        } else if (count == 0 && bytes_read == 0) { // Daca nu s-a citit nimic si nu e eroare
             printf("    (Nicio comoara gasita in acest hunt sau format invalid)\n");
        }
        printf("    ----\n");
    }
    close(fd);
    fflush(stdout);
    fflush(stderr);
}




// --- Functia Principala a Treasure Hub ---
int main() {
    char command_buffer[MAX_INPUT_BUFFER]; 
    char *cmd_token; 
    char *arg1 = NULL; 
    char *arg2 = NULL; 

    printf("Interfata Treasure Hub. Introduceti 'help' pentru comenzi.\n");

    if (setup_signal_handler(SIGCHLD, hub_sigchld_handler) == -1) {
        return EXIT_FAILURE;
    }

    while (1) {
        if (waiting_for_monitor_stop) {
            // Nu mai printam mesaj aici, SIGCHLD handler va re-afisa prompt-ul
            // printf("[Hub] Astept terminarea monitorului... (comenzi blocate)\n");
             while(waiting_for_monitor_stop) {
                 pause(); 
             }
            continue; 
        }

        printf("> "); 
        fflush(stdout);

        if (fgets(command_buffer, sizeof(command_buffer), stdin) == NULL) {
            if (feof(stdin)) { 
                printf("\n[Hub] EOF detectat. Iesire.\n");
                if (monitor_is_running) {
                    printf("[Hub] Trimit SIGTERM monitorului (PID %d) la iesire.\n", monitor_pid);
                    kill(monitor_pid, SIGTERM);
                    // Asteptam putin sa se proceseze, dar nu blocam la infinit
                    // waitpid(monitor_pid, NULL, 0);
                }
                break; 
            } else {
                perror("[Hub] Eroare la citirea comenzii");
                continue;
            }
        }

        command_buffer[strcspn(command_buffer, "\n")] = 0;

        cmd_token = strtok(command_buffer, " \t\n"); 
        if (cmd_token == NULL) continue; 

        arg1 = strtok(NULL, " \t\n"); 
        arg2 = strtok(NULL, " \t\n"); 
        
        // Verificam daca mai sunt argumente neasteptate
        char* rest = strtok(NULL, " \t\n");


        if (strcmp(cmd_token, "start_monitor") == 0) {
            if (arg1 != NULL) { 
                 fprintf(stderr, "[Hub] Eroare: Comanda 'start_monitor' nu necesita argumente.\n");
                 continue;
            }
            if (monitor_is_running) {
                fprintf(stderr, "[Hub] Eroare: Monitorul deja ruleaza (PID %d).\n", monitor_pid);
            } else {
                monitor_pid = fork(); 
                if (monitor_pid < 0) { 
                    perror("[Hub] Eroare la fork pentru monitor");
                }
                else if (monitor_pid == 0) { 
                    // Resetare handler SIGCHLD in copil la default sau ignorare
                    // pentru a nu interfera cu SIGCHLD-ul parintelui (hub)
                    // struct sigaction sa_dfl;
                    // memset(&sa_dfl, 0, sizeof(sa_dfl));
                    // sa_dfl.sa_handler = SIG_DFL;
                    // sigaction(SIGCHLD, &sa_dfl, NULL);
                    // Sau mai simplu, daca monitorul nu forkeaza el insusi copii pe care sa-i astepte:
                    signal(SIGCHLD, SIG_DFL);


                    monitor_main_loop();      
                    exit(EXIT_SUCCESS);       
                } else { 
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
                    monitor_is_running = 0; monitor_pid = 0;
                } else {
                    waiting_for_monitor_stop = 1; 
                    printf("[Hub] Astept terminarea monitorului... (comenzi blocate)\n");
                }
            }
        } else if (strcmp(cmd_token, "list_hunts") == 0) {
             if (arg1 != NULL) {
                 fprintf(stderr, "[Hub] Eroare: Comanda 'list_hunts' nu necesita argumente.\n");
                 continue;
             }
            if (!monitor_is_running) {
                fprintf(stderr, "[Hub] Eroare: Monitorul nu ruleaza pentru a executa 'list_hunts'.\n");
            } else {
                printf("[Hub] Trimit cerere catre monitor: list_hunts (SIGUSR1)\n");
                if (kill(monitor_pid, SIGUSR1) == -1) {
                    perror("[Hub] Eroare la trimiterea SIGUSR1");
                }
            }
        } 
        
        else if (strcmp(cmd_token, "list_treasures") == 0) {
            if (arg1 == NULL || arg2 != NULL) {
                fprintf(stderr, "[Hub] Utilizare: list_treasures <hunt_id>\n");
                continue;
            }
            if (!monitor_is_running) { 
                fprintf(stderr, "[Hub] Eroare: Monitorul nu ruleaza pentru a executa 'list_treasures'.\n");
            }
            else {
                FILE *fp_cmd = fopen(COMMAND_FILE, "w"); 
                if (!fp_cmd) {
                    perror("[Hub] Eroare la deschiderea fisierului de comanda");
                } else {
                    fprintf(fp_cmd, "list_treasures\n%s\n", arg1); 
                    fclose(fp_cmd);
                    printf("[Hub] Trimit cerere catre monitor: list_treasures pentru '%s' (SIGUSR2)\n", arg1);
                    if (kill(monitor_pid, SIGUSR2) == -1) {
                        perror("[Hub] Eroare la trimiterea SIGUSR2");
                    }
                }
            }
        }
        else if (strcmp(cmd_token, "view_treasure") == 0) {
            if (arg1 == NULL || arg2 == NULL || rest != NULL) { // Verificam si 'rest'
                fprintf(stderr, "[Hub] Utilizare: view_treasure <hunt_id> <treasure_id>\n");
                continue;
            }
            
            long treasure_id_val_long; // Validare ID
            char *endptr;
            errno = 0;
            treasure_id_val_long = strtol(arg2, &endptr, 10);
            if (errno != 0 || endptr == arg2 || (*endptr != '\0' && !isspace(*endptr)) || treasure_id_val_long <= 0 || treasure_id_val_long > INT_MAX) {
                fprintf(stderr, "[Hub] Eroare: treasure_id invalid '%s'. Trebuie sa fie un numar intreg pozitiv.\n", arg2);
                continue;
            }
        
            if (!monitor_is_running) { 
                 fprintf(stderr, "[Hub] Eroare: Monitorul nu ruleaza pentru a executa 'view_treasure'.\n");
            }
            else {
                FILE *fp_cmd = fopen(COMMAND_FILE, "w");
                if (!fp_cmd) {
                    perror("[Hub] Eroare la deschiderea fisierului de comanda");
                } else {
                    fprintf(fp_cmd, "view_treasure\n%s\n%s\n", arg1, arg2); 
                    fclose(fp_cmd);
                    printf("[Hub] Trimit cerere catre monitor: view_treasure pentru %s:%s (SIGUSR2)\n", arg1, arg2);
                    if (kill(monitor_pid, SIGUSR2) == -1) {
                        perror("[Hub] Eroare la trimiterea SIGUSR2");
                    }
                }
            }
        }
         else if (strcmp(cmd_token, "exit") == 0) {
            if (arg1 != NULL) {
                 fprintf(stderr, "[Hub] Eroare: Comanda 'exit' nu necesita argumente.\n");
                 continue;
            }
            if (monitor_is_running) {
                fprintf(stderr, "[Hub] Eroare: Monitorul (PID %d) inca ruleaza. Folositi 'stop_monitor' intai.\n", monitor_pid);
            } else {
                printf("[Hub] Iesire.\n");
                break; 
            }
        } else if (strcmp(cmd_token, "help") == 0) {
             if (arg1 != NULL) {
                 fprintf(stderr, "[Hub] Eroare: Comanda 'help' nu necesita argumente.\n");
                 continue;
             }
            printf("Comenzi disponibile:\n");
            printf("  start_monitor                - Porneste procesul monitor.\n");
            printf("  list_hunts                   - Cere monitorului sa listeze hunt-urile.\n");
            printf("  list_treasures <hunt_id>     - Cere monitorului sa listeze comori pentru un hunt.\n");
            printf("  view_treasure <h_id> <t_id>  - Cere monitorului sa vada o comoara specifica.\n");
            printf("  stop_monitor                 - Opreste monitorul si asteapta terminarea.\n");
            printf("  exit                         - Iese din hub (doar daca monitorul e oprit).\n");
            printf("  help                         - Afiseaza acest mesaj.\n");
        } else { 
            fprintf(stderr, "[Hub] Eroare: Comanda necunoscuta '%s'. Introduceti 'help'.\n", cmd_token);
        }
    } 

    // Cleanup command file if it exists from a previous run
    unlink(COMMAND_FILE); 
    printf("[Hub] Program terminat.\n");
    return EXIT_SUCCESS;
}
