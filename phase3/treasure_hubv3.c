#define _XOPEN_SOURCE 700 // Necesare pentru diverse functii POSIX (ex: sigaction)
#define _DEFAULT_SOURCE   // Pentru ctime, strsignal, si altele (ex: usleep, PATH_MAX din limits.h implicit)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>    // Pentru fork, pipe, exec, sleep, access, getpid, getppid, etc.
#include <fcntl.h>     // Pentru fcntl, O_NONBLOCK, open
#include <sys/stat.h>  // Pentru stat, mkdir, S_ISDIR, S_ISREG
#include <sys/types.h> // Pentru pid_t, mode_t, etc.
#include <sys/wait.h>  // Pentru waitpid, WIFEXITED, WEXITSTATUS, etc.
#include <signal.h>    // Pentru signal, sigaction, kill, semnale (SIGTERM, SIGUSR1, etc.)
#include <errno.h>     // Pentru errno, perror
#include <time.h>      // Pentru ctime (nu e folosit direct aici, dar e comun in astfel de programe)
#include <limits.h>    // Pentru PATH_MAX
#include <dirent.h>    // Pentru opendir, readdir, closedir
#include <ctype.h>     // Pentru isspace (folosit in parsarea inputului din Faza 1)
#include <stdarg.h>    // Pentru va_list, va_start, va_end, vsnprintf (in monitor_send_data)


#ifndef TREASURE_UTILS_H 
#define MAX_USERNAME_LEN 50
#define MAX_CLUE_LEN 256
#define MAX_INPUT_BUFFER 512 // Buffer general pentru citirea liniilor
#define MAX_PATH_LEN PATH_MAX  // Lungimea maxima a unei cai, definita in limits.h
#define TREASURE_FILE_NAME "treasures.bin" // Numele fisierului binar cu comori
#define DIR_PERMS 0755  // Permisiuni pentru directoare create (rwxr-xr-x)
#define FILE_PERMS 0644 // Permisiuni pentru fisiere create (rw-r--r--)
#define COMMAND_FILE "monitor_command.tmp" // Fisier pentru comunicarea comenzilor detaliate la monitor
#define MAX_USERS 100 // Limita pentru score_calculator 

// --- Structuri de date 
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
#endif


// --- Variabile Globale pentru Starea Hub-ului și Comunicare ---

// Pipe pentru comunicarea datelor de la Monitor la Hub:
// pipe_MtoH_fd[0] - capatul de citire (folosit de Hub)
// pipe_MtoH_fd[1] - capatul de scriere (folosit de Monitor)
int pipe_MtoH_fd[2];

// Descriptorul de fisier pentru capatul de scriere al pipe-ului MtoH,
// stocat in procesul Monitor pentru a putea scrie date catre Hub.
int monitor_write_pipe_fd = -1; // Initializat la -1 (invalid)

// Flag-uri pentru starea procesului Monitor, vizibile global in Hub
volatile sig_atomic_t monitor_is_running = 0;       // 1 daca monitorul ruleaza, 0 altfel
volatile sig_atomic_t waiting_for_monitor_stop = 0; // 1 daca Hub asteapta oprirea monitorului
pid_t monitor_pid = 0;                              // PID-ul procesului monitor (0 daca nu ruleaza)

// Flag-uri de semnal pentru procesul Monitor (setate de handler-ele Monitorului)
volatile sig_atomic_t sigusr1_received_monitor = 0; // SIGUSR1 primit de Monitor (pentru list_hunts)
volatile sig_atomic_t sigusr2_received_monitor = 0; // SIGUSR2 primit de Monitor (pentru comenzi din fisier)
volatile sig_atomic_t sigterm_received_monitor = 0; // SIGTERM primit de Monitor (pentru oprire)

// Flag de semnal pentru procesul Hub (setat de handler-ul Hub-ului)
// Indica faptul ca Monitorul a trimis date si sunt gata de citit in pipe_MtoH_fd[0]
volatile sig_atomic_t sigusr1_received_hub_data_ready = 0;


// --- Handlers de Semnal ---

// Handler-ele de semnal pentru procesul MONITOR (simple, doar seteaza flag-uri)
void monitor_sigusr1_handler(int signum) { (void)signum; sigusr1_received_monitor = 1; }
void monitor_sigusr2_handler(int signum) { (void)signum; sigusr2_received_monitor = 1; }
void monitor_sigterm_handler(int signum) { (void)signum; sigterm_received_monitor = 1; }

// Handler-ul SIGUSR1 pentru procesul HUB
// Acest semnal este trimis de Monitor catre Hub pentru a indica ca datele sunt gata in pipe.
void hub_sigusr1_data_ready_handler(int signum) {
    (void)signum; // Ignora parametrul signum
    sigusr1_received_hub_data_ready = 1; // Seteaza flag-ul global
}

// Handler-ul SIGCHLD pentru procesul HUB
// Acest handler este apelat cand un proces copil al Hub-ului se termina.
// Poate fi Monitorul sau un proces `score_calculator`.
void hub_sigchld_handler(int signum) {
    (void)signum; // Ignora parametrul signum
    int status;         // Pentru a stoca statusul de iesire al copilului
    pid_t terminated_pid; // PID-ul copilului care s-a terminat

    // Folosim o bucla cu waitpid si WNOHANG pentru a gestiona toti copiii
    // care s-ar fi putut termina simultan (non-blocking wait).
    while ((terminated_pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (terminated_pid == monitor_pid) { // Daca copilul terminat este Monitorul
            printf("\n[Hub] Procesul monitor (PID %d) s-a terminat.\n", terminated_pid);
            // Afisam cum s-a terminat Monitorul
            if (WIFEXITED(status)) {
                printf("[Hub] Monitorul a iesit normal cu status %d.\n", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("[Hub] Monitorul a fost terminat de semnalul %d (%s).\n", WTERMSIG(status), strsignal(WTERMSIG(status)));
            }
            // Resetam starea globala a Hub-ului referitoare la Monitor
            monitor_pid = 0;
            monitor_is_running = 0;
            waiting_for_monitor_stop = 0;
            // Inchidem capatul de citire al pipe-ului MtoH, deoarece Monitorul s-a terminat
            if (pipe_MtoH_fd[0] != -1) {
                close(pipe_MtoH_fd[0]);
                pipe_MtoH_fd[0] = -1; // Marcam ca inchis
            }
            // Capatul de scriere (pipe_MtoH_fd[1]) ar fi trebuit sa fie inchis de Monitor la iesire,
            // sau de Hub la fork (in partea parintelui).
            printf("> "); // Reafisam prompt-ul Hub-ului
            fflush(stdout);
        } else {
            // Daca un alt copil s-a terminat (ex: un `score_calculator`)
            // In designul curent, `calculate_score` foloseste waitpid blocant,
            // deci acest SIGCHLD ar putea fi pentru un scorer care a terminat
            // DACA waitpid din `handle_calculate_score` ar fi WNOHANG sau nu ar fi apelat.
            // Momentan, acest `else` nu ar trebui sa prinda scorerele in mod normal.
            // printf("[Hub] Proces copil (PID %d) s-a terminat (posibil score_calculator).\n", terminated_pid);
        }
    }
}

// Functie ajutatoare pentru configurarea unui handler de semnal folosind sigaction
int setup_signal_handler(int signum, void (*handler)(int)) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa)); // Initializam structura cu zero
    sa.sa_handler = handler;    // Setam functia handler
    sigemptyset(&sa.sa_mask);   // Nu blocam alte semnale in timpul executiei handler-ului
    sa.sa_flags = SA_RESTART;   // Important: reporneste apelurile de sistem intrerupte de semnal
    if (sigaction(signum, &sa, NULL) == -1) { // Aplicam configuratia
        char msg[100];
        snprintf(msg, sizeof(msg), "Eroare la configurarea sigaction pentru semnalul %d", signum);
        perror(msg); // Afisam eroarea sistemului
        return -1; // Eroare
    }
    return 0; // Succes
}


// --- Functii Helper pentru Procesul MONITOR ---

// Trimite date formatate prin pipe-ul Monitorului catre Hub.
// Foloseste argumente variabile, similar cu printf.
void monitor_send_data(const char *format, ...) {
    char buffer[MAX_INPUT_BUFFER * 4]; // Buffer suficient de mare pentru majoritatea mesajelor
    va_list args; // Lista de argumente variabile

    va_start(args, format); // Initializam lista de argumente
    // Cream string-ul formatat in buffer. vsnprintf previne buffer overflow.
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args); // Inchidem lista de argumente

    if (monitor_write_pipe_fd != -1) { // Verificam daca descriptorul de scriere este valid
        ssize_t written = write(monitor_write_pipe_fd, buffer, strlen(buffer));
        if (written < 0) {
            // Daca Hub-ul a inchis pipe-ul, errno ar fi EPIPE.
            // Daca SIGPIPE nu e ignorat, procesul ar fi terminat.
            perror("[Monitor] Eroare la scrierea in pipe spre Hub");
        }
        
    } else {
        // Acest mesaj ar aparea pe stderr-ul Monitorului, nu trimis la Hub.
        fprintf(stderr, "[Monitor] Eroare: Capatul de scriere al pipe-ului spre Hub nu este valid.\n");
    }
}

// --- Functiile Procesului MONITOR ---

// MONITOR: Listeaza hunt-urile si numarul de comori, trimitand output-ul la Hub.
void monitor_list_hunts() {
    // Trimite un antet prin pipe
    monitor_send_data("--- [Monitor Results] Hunt-uri Descoperite ---\n");
    DIR *dirp = opendir("."); // Deschide directorul curent
    if (!dirp) {
        char err_msg[200];
        snprintf(err_msg, sizeof(err_msg), "[Monitor] Eroare la deschiderea directorului curent (.): %s\n", strerror(errno));
        monitor_send_data("%s", err_msg);
        monitor_send_data("-------------------------------------\n");
        return;
    }

    struct dirent *entry;     // Pentru fiecare intrare din director
    struct stat st_dir;       // Pentru a verifica daca intrarea e director
    int hunt_count = 0;       // Numarul de hunt-uri valide gasite
    char path_buffer[MAX_PATH_LEN]; // Pentru a construi caile

    // Parcurge intrarile din directorul curent
    while ((entry = readdir(dirp)) != NULL) {
        snprintf(path_buffer, sizeof(path_buffer), "./%s", entry->d_name); // Calea relativa
        if (stat(path_buffer, &st_dir) == 0) { // Obtine informatii despre intrare
            // Verifica daca e director si nu e "." sau ".."
            if (S_ISDIR(st_dir.st_mode) && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                // Verifica daca directorul este un hunt valid (contine treasures.bin)
                char treasure_bin_path[MAX_PATH_LEN];
                snprintf(treasure_bin_path, sizeof(treasure_bin_path), "./%s/%s", entry->d_name, TREASURE_FILE_NAME);
                struct stat treasure_stat_check;
                if (stat(treasure_bin_path, &treasure_stat_check) == 0 && S_ISREG(treasure_stat_check.st_mode)) {
                    // Calculeaza numarul de comori (local, fara a apela o alta functie care trimite prin pipe)
                    int fd_count = open(treasure_bin_path, O_RDONLY);
                    int treasure_count = 0;
                    if (fd_count != -1) {
                        Treasure t; // Structura temporara pentru citire
                        // Citeste toate structurile Treasure complete din fisier
                        while (read(fd_count, &t, sizeof(Treasure)) == sizeof(Treasure)) {
                            treasure_count++;
                        }
                        close(fd_count);
                    }
                    // Trimite informatia despre hunt la Hub
                    monitor_send_data("  Hunt ID: %-20s (%d comori)\n", entry->d_name, treasure_count);
                    hunt_count++;
                }
            }
        }
    }
    closedir(dirp); // Inchide directorul

    if (hunt_count == 0) {
        monitor_send_data("  (Niciun hunt valid gasit)\n");
    }
    monitor_send_data("-------------------------------------\n");
}

// MONITOR: Listeaza comorile dintr-un hunt specific, trimitand output-ul la Hub.
void monitor_list_treasures_for_hunt(const char *hunt_id) {
    char treasure_file_path[MAX_PATH_LEN];
    snprintf(treasure_file_path, sizeof(treasure_file_path), "./%s/%s", hunt_id, TREASURE_FILE_NAME);

    // Verifica daca hunt_id este un director valid
    struct stat hunt_st;
    char hunt_dir_path[MAX_PATH_LEN];
    snprintf(hunt_dir_path, sizeof(hunt_dir_path), "./%s", hunt_id);
    if (stat(hunt_dir_path, &hunt_st) == -1 || !S_ISDIR(hunt_st.st_mode)) {
        monitor_send_data("[Monitor Results] Eroare: Hunt ID '%s' nu este un director valid sau nu exista.\n", hunt_id);
        return;
    }

    // Deschide fisierul de comori
    int fd = open(treasure_file_path, O_RDONLY);
    if (fd == -1) { // Daca deschiderea esueaza
        if (errno == ENOENT) { // Fisierul nu exista (hunt gol sau fara treasures.bin)
            monitor_send_data("--- [Monitor Results] Comori in Hunt: %s ---\n", hunt_id);
            monitor_send_data("    (Niciun fisier de comori '%s' gasit in acest hunt sau hunt-ul este gol)\n", TREASURE_FILE_NAME);
            monitor_send_data("    ----\n");
        } else { // Alta eroare la deschidere
            char err_msg[300];
            snprintf(err_msg, sizeof(err_msg), "[Monitor Results] Avertisment: Nu pot deschide %s pentru hunt '%s': %s\n",
                     TREASURE_FILE_NAME, hunt_id, strerror(errno));
            monitor_send_data("%s", err_msg);
        }
        return;
    }

    monitor_send_data("--- [Monitor Results] Comori in Hunt: %s ---\n", hunt_id);
    Treasure current_treasure; // Buffer pentru citirea unei comori
    ssize_t bytes_read;        // Numarul de octeti cititi
    int count = 0;             // Numarul de comori listate
    char treasure_buffer[MAX_INPUT_BUFFER * 2]; // Buffer pentru formatarea detaliilor unei comori

    // Citeste comorile din fisier
    while ((bytes_read = read(fd, &current_treasure, sizeof(Treasure))) > 0) {
        if (bytes_read < sizeof(Treasure)) { // Citire partiala, fisier posibil corupt
            monitor_send_data("[Monitor Results] Avertisment: Fisierul '%s' pare corupt (citire partiala).\n", treasure_file_path);
            break;
        }
        count++;
        // Formateaza detaliile comorii si le trimite la Hub
        snprintf(treasure_buffer, sizeof(treasure_buffer),
                 "    ID:          %d\n    Utilizator:  %s\n    GPS (Lat,Lon): (%.6f, %.6f)\n    Indiciu:     \"%s\"\n    Valoare:     %d\n    ----\n",
                 current_treasure.id, current_treasure.username, current_treasure.coordinates.latitude,
                 current_treasure.coordinates.longitude, current_treasure.clue, current_treasure.value);
        monitor_send_data("%s", treasure_buffer);
    }

    if (bytes_read < 0) { // Eroare la citire
        char err_msg[300];
        snprintf(err_msg, sizeof(err_msg), "[Monitor Results] Eroare la citirea fisierului '%s': %s\n", treasure_file_path, strerror(errno));
        monitor_send_data("%s", err_msg);
    }
    // Daca fisierul a fost citit complet (bytes_read == 0) si nu s-au gasit comori (count == 0)
    if (count == 0 && bytes_read == 0) {
         struct stat file_st_check; // Verificam daca fisierul e pur si simplu gol
        if (stat(treasure_file_path, &file_st_check) == 0 && file_st_check.st_size == 0) {
             monitor_send_data("    (Fisierul de comori este gol)\n");
        } else { // Sau format invalid / alte motive
             monitor_send_data("    (Nicio comoara gasita in acest hunt sau format invalid)\n");
        }
        monitor_send_data("    ----\n");
    }
    close(fd); // Inchide fisierul
}

// MONITOR: Proceseaza comanda view_treasure.
// Forkeaza treasure_manager, ii captureaza output-ul printr-un pipe si il trimite la Hub.
void monitor_process_view_treasure(const char* hunt_id_arg, const char* treasure_id_str_arg) {
    // Validare treasure_id (nu mai convertim la int aici, treasure_manager o face)
    long treasure_id_val_long;
    char *endptr;
    errno = 0; // Reseteaza errno inainte de strtol
    treasure_id_val_long = strtol(treasure_id_str_arg, &endptr, 10);
    // Verificari pentru strtol: errno setat, niciun caracter convertit, caractere invalide dupa numar, out of range (desi INT_MAX e verificat)
    if (errno != 0 || endptr == treasure_id_str_arg || (*endptr != '\0' && !isspace(*endptr)) || treasure_id_val_long <= 0 /* treasure_id e pozitiv */ || treasure_id_val_long > INT_MAX) {
         monitor_send_data("[Monitor Results] Eroare: treasure_id '%s' invalid.\n", treasure_id_str_arg);
         return;
    }

    int pipe_TMtoM_fd[2]; // Pipe local: TreasureManager (output) -> Monitor (input)
    if (pipe(pipe_TMtoM_fd) == -1) { // Creeaza pipe-ul
        char err_msg[200];
        snprintf(err_msg, sizeof(err_msg), "[Monitor] Eroare la crearea pipe-ului TMtoM: %s\n", strerror(errno));
        monitor_send_data("[Monitor Results] Eroare interna la procesarea view_treasure (pipe create failed).\n");
        monitor_send_data("%s", err_msg);
        return;
    }

    pid_t viewer_pid = fork(); // Creeaza procesul copil pentru treasure_manager
    if (viewer_pid < 0) { // Eroare la fork
        char err_msg[200];
        snprintf(err_msg, sizeof(err_msg), "[Monitor] Eroare la fork pentru treasure_manager: %s\n", strerror(errno));
        monitor_send_data("[Monitor Results] Eroare interna la procesarea view_treasure (fork failed).\n");
        monitor_send_data("%s", err_msg);
        close(pipe_TMtoM_fd[0]); // Inchide ambele capete ale pipe-ului local
        close(pipe_TMtoM_fd[1]);
        return;
    } else if (viewer_pid == 0) { // Proces copil (va deveni treasure_manager)
        // Copilul nu foloseste pipe-ul Monitor->Hub
        if (pipe_MtoH_fd[0] != -1) close(pipe_MtoH_fd[0]); // Capatul de citire al Hub-ului
        if(monitor_write_pipe_fd != -1) close(monitor_write_pipe_fd); // Capatul de scriere al Monitorului

        // Configurarea pipe-ului TMtoM pentru copil
        close(pipe_TMtoM_fd[0]);    // Copilul inchide capatul de citire al pipe-ului TMtoM

        // Redirecteaza stdout si stderr copilului catre capatul de scriere al pipe-ului TMtoM
        // Astfel, tot ce scrie treasure_manager pe stdout/stderr ajunge in pipe.
        if (dup2(pipe_TMtoM_fd[1], STDOUT_FILENO) == -1) {
            perror("[TreasureManager Child] Eroare la dup2 pentru STDOUT");
            exit(EXIT_FAILURE); // Iesire daca redirectarea esueaza
        }
        if (dup2(pipe_TMtoM_fd[1], STDERR_FILENO) == -1) {
            perror("[TreasureManager Child] Eroare la dup2 pentru STDERR");
            exit(EXIT_FAILURE);
        }
        close(pipe_TMtoM_fd[1]);    // Inchide descriptorul original dupa dup2, acum e redundant

        // Executa treasure_manager
        // Primul argument este calea/numele executabilului.
        // Urmatoarele sunt argumentele pentru main() al treasure_manager (argv[0], argv[1], ...).
        // Ultimul argument trebuie sa fie (char *)NULL.
        execlp("./treasure_manager", "treasure_manager", "view", hunt_id_arg, treasure_id_str_arg, (char *)NULL);
        
        // Daca execlp returneaza, inseamna ca a esuat
        perror("[TreasureManager Child] Eroare la execlp treasure_manager");
        exit(EXIT_FAILURE); // Iesire copil in caz de eroare exec
    } else { // Proces parinte (Monitor)
        // Parintele (Monitor) inchide capatul de scriere al pipe-ului TMtoM
        close(pipe_TMtoM_fd[1]);

        char buffer[1024]; // Buffer pentru a citi output-ul de la treasure_manager
        ssize_t bytes_read_tm; // Numarul de octeti cititi din pipe-ul TMtoM

        // Citeste output-ul de la treasure_manager (din pipe_TMtoM_fd[0])
        // si il trimite direct la Hub (prin pipe_MtoH_fd, folosind monitor_send_data)
        while ((bytes_read_tm = read(pipe_TMtoM_fd[0], buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes_read_tm] = '\0'; // Asigura null-termination
            monitor_send_data("%s", buffer); // Trimite datele citite catre Hub
        }
        // Verificam daca a fost o eroare la citire (bytes_read_tm < 0)
        if (bytes_read_tm < 0) {
            char err_msg[200];
            snprintf(err_msg,sizeof(err_msg), "[Monitor] Eroare la citirea din pipe-ul TMtoM: %s\n", strerror(errno));
            monitor_send_data("[Monitor Results] Eroare interna la citirea output-ului de la treasure_manager.\n");
            monitor_send_data("%s", err_msg);
        }
        // Dupa ce s-a terminat citirea (EOF sau eroare), inchidem capatul de citire
        close(pipe_TMtoM_fd[0]);

        // Asteptam terminarea procesului copil treasure_manager
        int viewer_status;
        waitpid(viewer_pid, &viewer_status, 0);
        // Statusul lui treasure_manager nu este explicit trimis la Hub, doar output-ul sau.
       
    }
}

// MONITOR: Citeste si proceseaza comanda din fisierul COMMAND_FILE.
void monitor_process_command_file() {
    FILE *fp_cmd = fopen(COMMAND_FILE, "r");
    if (!fp_cmd) {
        // Nu trimitem eroare pe pipe daca fisierul nu exista,
        // poate fi o conditie normala (ex: semnal SIGUSR2 trimis fara ca fisierul sa fie creat).
        return;
    }

    char command_type[100];
    char hunt_id_arg[MAX_PATH_LEN];
    char treasure_id_str_arg[100];

    // Citeste tipul comenzii (prima linie)
    if (fgets(command_type, sizeof(command_type), fp_cmd) == NULL) {
        fclose(fp_cmd); unlink(COMMAND_FILE); // Inchide si sterge fisierul
        monitor_send_data("[Monitor Results] Eroare: Fisier comanda gol sau format invalid.\n");
        return;
    }
    command_type[strcspn(command_type, "\n")] = 0; // Elimina newline

    // Proceseaza comanda
    if (strcmp(command_type, "list_treasures") == 0) {
        if (fgets(hunt_id_arg, sizeof(hunt_id_arg), fp_cmd) != NULL) {
            hunt_id_arg[strcspn(hunt_id_arg, "\n")] = 0;
            monitor_list_treasures_for_hunt(hunt_id_arg);
        } else {
            monitor_send_data("[Monitor Results] Eroare: Format invalid pentru list_treasures (lipsa hunt_id).\n");
        }
    } else if (strcmp(command_type, "view_treasure") == 0) {
        if (fgets(hunt_id_arg, sizeof(hunt_id_arg), fp_cmd) != NULL &&
            fgets(treasure_id_str_arg, sizeof(treasure_id_str_arg), fp_cmd) != NULL) {
            hunt_id_arg[strcspn(hunt_id_arg, "\n")] = 0;
            treasure_id_str_arg[strcspn(treasure_id_str_arg, "\n")] = 0;
            monitor_process_view_treasure(hunt_id_arg, treasure_id_str_arg);
        } else {
            monitor_send_data("[Monitor Results] Eroare: Format invalid pentru view_treasure (lipsa argumente).\n");
        }
    } else {
        monitor_send_data("[Monitor Results] Eroare: Tip comanda necunoscut '%s' in fisierul de comanda.\n", command_type);
    }

    fclose(fp_cmd);
    unlink(COMMAND_FILE); // Sterge fisierul de comanda dupa procesare
}

// MONITOR: Bucla principala de executie a procesului Monitor.
void monitor_main_loop(int write_pipe_to_hub_fd) {
    // Salveaza descriptorul de scriere al pipe-ului catre Hub
    monitor_write_pipe_fd = write_pipe_to_hub_fd;
    // Mesaj de debug (pe stdout-ul original al Monitorului, care ar putea fi /dev/null sau terminal daca nu e redirectat)
    // printf("[Monitor %d] Pornit. Scrie pe pipe-ul cu descriptorul %d.\n", getpid(), monitor_write_pipe_fd);
    // fflush(stdout);

    // Configureaza handler-ele de semnal pentru Monitor
    setup_signal_handler(SIGUSR1, monitor_sigusr1_handler);
    setup_signal_handler(SIGUSR2, monitor_sigusr2_handler);
    setup_signal_handler(SIGTERM, monitor_sigterm_handler);

    // Monitorul nu gestioneaza SIGCHLD-ul propriilor copii (treasure_manager)
    // foloseste waitpid blocant.
    // Resetam SIGCHLD la default pentru a nu interfera cu handler-ul Hub-ului.
    signal(SIGCHLD, SIG_DFL);

    pid_t hub_pid = getppid(); // Obtine PID-ul procesului parinte (Hub)

    // Bucla principala: asteapta semnale si reactioneaza
    while (!sigterm_received_monitor) { // Ruleaza pana la primirea SIGTERM
        if (sigusr1_received_monitor) { // Daca a primit SIGUSR1 (list_hunts)
            sigusr1_received_monitor = 0; // Reseteaza flag-ul
            monitor_list_hunts();         // Executa actiunea
            // Trimite semnal SIGUSR1 la Hub pentru a-l notifica ca datele sunt gata
            if (kill(hub_pid, SIGUSR1) == -1) {
                perror("[Monitor] Eroare la trimiterea semnalului SIGUSR1 catre Hub");
            }
        }
        if (sigusr2_received_monitor) { // Daca a primit SIGUSR2 (comanda din fisier)
            sigusr2_received_monitor = 0; // Reseteaza flag-ul
            monitor_process_command_file(); // Executa actiunea
            // Trimite semnal SIGUSR1 la Hub pentru a-l notifica ca datele sunt gata
            if (kill(hub_pid, SIGUSR1) == -1) {
                 perror("[Monitor] Eroare la trimiterea semnalului SIGUSR1 catre Hub dupa SIGUSR2");
            }
        }
        // `pause()` suspenda procesul pana la primirea unui semnal.
        // Dupa ce handler-ul semnalului ruleaza, `pause()` returneaza -1 cu `errno = EINTR`.
        // Bucla `while` va reevalua apoi flag-urile.
        pause();
    }

    // Sectiune de curatenie la primirea SIGTERM
    // printf("[Monitor %d] SIGTERM primit. Curatenie si iesire...\n", getpid()); fflush(stdout);
    
    // Inchide capatul de scriere al pipe-ului catre Hub.
    // Acest lucru va semnala EOF Hub-ului cand va incerca sa citeasca.
    if (monitor_write_pipe_fd != -1) {
        close(monitor_write_pipe_fd);
        monitor_write_pipe_fd = -1; // Marcam ca inchis
    }

    sleep(1); // Simulare timp de curatenie
    // printf("[Monitor %d] Iesire acum.\n", getpid()); fflush(stdout);
    exit(EXIT_SUCCESS); // Iesire normala din Monitor
}


// --- Functii pentru Procesul HUB (main si functiile de comanda) ---

// HUB: Citeste datele trimise de Monitor prin pipe si le afiseaza.
void hub_read_from_monitor_pipe() {
    char buffer[1024 + 1]; // Buffer pentru citire (+1 pentru null terminator)
    ssize_t bytes_read;    // Numarul de octeti cititi

    // Setam capatul de citire al pipe-ului in mod non-blocant.
    // Acest lucru este util pentru a nu bloca Hub-ul daca semnalul "data gata"
    // a fost primit, dar datele intarzie sau au fost deja citite.
    int original_flags = fcntl(pipe_MtoH_fd[0], F_GETFL, 0); // Obtinem flag-urile curente
    if (original_flags == -1) {
        perror("[Hub] Eroare la fcntl F_GETFL pe pipe-ul monitorului");
        sigusr1_received_hub_data_ready = 0; // Resetam flagul daca nu putem citi
        return;
    }
    if (fcntl(pipe_MtoH_fd[0], F_SETFL, original_flags | O_NONBLOCK) == -1) { // Adaugam O_NONBLOCK
        perror("[Hub] Eroare la fcntl F_SETFL O_NONBLOCK pe pipe-ul monitorului");
        sigusr1_received_hub_data_ready = 0;
        return;
    }

    int total_bytes_read_session = 0; // Contorizam cat s-a citit in aceasta "sesiune"
    // Bucla de citire: citeste cat timp exista date in pipe sau pana la eroare.
    while ((bytes_read = read(pipe_MtoH_fd[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';  // Asigura null-termination
        printf("%s", buffer);       // Afiseaza datele primite
        total_bytes_read_session += bytes_read;
    }
    fflush(stdout); // Asigura afisarea completa

    // Dupa bucla, verificam de ce s-a oprit citirea
    if (bytes_read == -1) { // read() a returnat eroare
        // Daca eroarea este EAGAIN sau EWOULDBLOCK, inseamna ca nu mai sunt date
        // de citit in mod non-blocant, ceea ce este normal.
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("[Hub] Eroare la citirea din pipe-ul monitorului");
        }
        // Daca e EAGAIN/EWOULDBLOCK, nu facem nimic, inseamna ca am citit tot ce era disponibil.
    } else if (bytes_read == 0) { // read() a returnat 0
        // Acest lucru inseamna EOF - capatul de scriere al pipe-ului a fost inchis (Monitorul s-a terminat).
        // printf("[Hub] EOF detectat pe pipe-ul monitorului. Monitorul s-a inchis probabil.\n");
        // Handler-ul SIGCHLD ar trebui sa se ocupe de resetarea starii monitorului.
        // Inchidem si noi capatul de citire daca nu e deja inchis.
        if (pipe_MtoH_fd[0] != -1) {
            // close(pipe_MtoH_fd[0]); // SIGCHLD handler face asta.
            // pipe_MtoH_fd[0] = -1;
        }
    }
    // Daca total_bytes_read_session este 0, dar semnalul a fost primit,
    // inseamna ca datele au fost citite intr-un apel anterior sau Monitorul nu a scris nimic.

    // Resetam flag-ul semnalului dupa ce am incercat sa citim
    sigusr1_received_hub_data_ready = 0;

    // Restauram flag-urile originale ale pipe-ului (optional, dar curat)
    // Daca pipe-ul e inca valid (nu a fost inchis de SIGCHLD/EOF)
    if (pipe_MtoH_fd[0] != -1) {
        if (fcntl(pipe_MtoH_fd[0], F_SETFL, original_flags) == -1) {
            perror("[Hub] Eroare la fcntl F_SETFL restaurare flag-uri pe pipe-ul monitorului");
        }
    }
}

// HUB: Gestioneaza comanda `calculate_score`.
// Pentru fiecare hunt, forkeaza `score_calculator`, captureaza output-ul si il afiseaza.
void handle_calculate_score() {
    printf("\n[Hub] Calculare scoruri...\n");
    DIR *dirp = opendir("."); // Deschide directorul curent
    if (!dirp) {
        perror("[Hub] Eroare la deschiderea directorului curent pentru calculate_score");
        return;
    }

    struct dirent *entry;
    struct stat st_dir;
    char path_buffer[MAX_PATH_LEN];
    int hunts_found_for_score = 0; // Contor pentru hunt-uri procesate

    // Itereaza prin intrarile din directorul curent
    while ((entry = readdir(dirp)) != NULL) {
        snprintf(path_buffer, sizeof(path_buffer), "./%s", entry->d_name);
        if (stat(path_buffer, &st_dir) == 0) { // Obtine informatii despre intrare
            // Verifica daca este un director valid si nu "." sau ".."
            if (S_ISDIR(st_dir.st_mode) && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                // Verifica daca directorul este un hunt (contine treasures.bin)
                char treasure_bin_path[MAX_PATH_LEN];
                snprintf(treasure_bin_path, sizeof(treasure_bin_path), "./%s/%s", entry->d_name, TREASURE_FILE_NAME);
                struct stat treasure_stat_check;
                if (stat(treasure_bin_path, &treasure_stat_check) == 0 && S_ISREG(treasure_stat_check.st_mode)) {
                    hunts_found_for_score++;
                    

                    int pipe_score_fd[2]; // Pipe local: score_calculator -> Hub
                    if (pipe(pipe_score_fd) == -1) { // Creeaza pipe-ul
                        perror("[Hub] Eroare la crearea pipe-ului pentru score_calculator");
                        continue; // Treci la urmatorul hunt
                    }

                    pid_t scorer_pid = fork(); // Creeaza procesul copil pentru score_calculator
                    if (scorer_pid < 0) { // Eroare la fork
                        perror("[Hub] Eroare la fork pentru score_calculator");
                        close(pipe_score_fd[0]); close(pipe_score_fd[1]);
                        continue;
                    } else if (scorer_pid == 0) { // Proces copil (va deveni score_calculator)
                        // Copilul nu foloseste pipe-ul Monitor<->Hub
                        if (pipe_MtoH_fd[0] != -1) close(pipe_MtoH_fd[0]);
                        if (pipe_MtoH_fd[1] != -1) close(pipe_MtoH_fd[1]); // Chiar daca e al parintelui, il inchide din perspectiva copilului.

                        close(pipe_score_fd[0]); // Copilul inchide capatul de citire
                        // Redirecteaza stdout-ul copilului catre capatul de scriere al pipe-ului
                        if (dup2(pipe_score_fd[1], STDOUT_FILENO) == -1) {
                            perror("[ScoreCalculator Child] Eroare la dup2 STDOUT");
                            exit(EXIT_FAILURE);
                        }
                        // stderr-ul lui score_calculator va merge la terminalul Hub-ului,
                        // ceea ce e util pentru debug. Daca nu se doreste, se poate redirecta la /dev/null.
                        close(pipe_score_fd[1]); // Inchide descriptorul original

                        // Executa score_calculator
                        execlp("./score_calculator", "score_calculator", entry->d_name, (char *)NULL);
                        // Daca execlp esueaza
                        perror("[ScoreCalculator Child] Eroare la execlp score_calculator");
                        exit(EXIT_FAILURE);
                    } else { // Proces parinte (Hub)
                        close(pipe_score_fd[1]); // Parintele inchide capatul de scriere

                        char score_buffer[1024 + 1];
                        ssize_t bytes_read_score;
                        // Citeste output-ul de la score_calculator din pipe
                        while ((bytes_read_score = read(pipe_score_fd[0], score_buffer, sizeof(score_buffer) - 1)) > 0) {
                            score_buffer[bytes_read_score] = '\0';
                            printf("%s", score_buffer); // Afiseaza direct
                        }
                         if (bytes_read_score < 0) { // Eroare la citire
                             perror("[Hub] Eroare la citirea din pipe-ul score_calculator");
                         }
                        close(pipe_score_fd[0]); // Inchide capatul de citire
                        waitpid(scorer_pid, NULL, 0); // Asteapta terminarea procesului score_calculator
                    }
                }
            }
        }
    }
    closedir(dirp); // Inchide directorul
    if (hunts_found_for_score == 0) {
        printf("[Hub] Niciun hunt valid gasit pentru calcularea scorurilor.\n");
    }
    printf("----------------------------------\n"); // Separator final
    fflush(stdout);
}

// HUB: Functia principala a programului Treasure Hub.
int main() {
    char command_buffer[MAX_INPUT_BUFFER]; // Buffer pentru comanda citita
    char *cmd_token, *arg1 = NULL, *arg2 = NULL, *rest = NULL; // Pentru parsarea comenzii

    // Initializam descriptorii pipe-ului MtoH ca fiind necreati/invalidi
    pipe_MtoH_fd[0] = -1;
    pipe_MtoH_fd[1] = -1;

    printf("Interfata Treasure Hub (Phase 3). Introduceti 'help' pentru comenzi.\n");

    // Configureaza handler-ele de semnal pentru Hub
    setup_signal_handler(SIGCHLD, hub_sigchld_handler); // Pentru terminarea copiilor
    setup_signal_handler(SIGUSR1, hub_sigusr1_data_ready_handler); // Pentru notificarea de la Monitor

    
    signal(SIGPIPE, SIG_IGN);

    // Bucla principala de comenzi a Hub-ului
    while (1) {
        // Daca Hub-ul asteapta oprirea Monitorului, intra intr-o bucla de pauza
        if (waiting_for_monitor_stop) {
             while(waiting_for_monitor_stop) { pause(); } // Asteapta SIGCHLD
            // Dupa ce waiting_for_monitor_stop devine 0 (in SIGCHLD handler),
            // bucla exterioara continua si va reafisa promptul.
            continue;
        }

        // Verifica daca Monitorul a trimis date (flag setat de hub_sigusr1_data_ready_handler)
        if (sigusr1_received_hub_data_ready) {
            hub_read_from_monitor_pipe(); // Citeste si afiseaza datele
            // Prompt-ul va fi afisat mai jos, dupa ce s-au citit datele.
        }

        printf("> "); // Afiseaza prompt-ul
        fflush(stdout);

        // Citeste comanda de la utilizator
        if (fgets(command_buffer, sizeof(command_buffer), stdin) == NULL) {
            if (feof(stdin)) { // EOF (Ctrl+D)
                printf("\n[Hub] EOF detectat. Iesire.\n");
                if (monitor_is_running) { // Daca Monitorul inca ruleaza
                    printf("[Hub] Trimit SIGTERM monitorului (PID %d) la iesire.\n", monitor_pid);
                    kill(monitor_pid, SIGTERM);
                    // O mica pauza pentru a permite Monitorului sa proceseze SIGTERM si sa se inchida.
                    // Nu asteptam blocant la infinit aici, deoarece Hub-ul trebuie sa iasa.
                    sleep(1);
                    // O incercare non-blocanta de a curata procesul monitor, daca s-a terminat rapid.
                    if(monitor_pid != 0) waitpid(monitor_pid, NULL, WNOHANG);
                }
                break; // Iese din bucla principala
            } else { // Alta eroare la fgets
                perror("[Hub] Eroare la citirea comenzii");
                continue;
            }
        }

        // --- Parsare Comanda ---
        command_buffer[strcspn(command_buffer, "\n")] = 0; // Elimina newline
        cmd_token = strtok(command_buffer, " \t\n");      // Extrage comanda
        if (cmd_token == NULL) continue;                   // Linie goala, reia bucla

        arg1 = strtok(NULL, " \t\n"); // Primul argument
        arg2 = strtok(NULL, " \t\n"); // Al doilea argument
        rest = strtok(NULL, " \t\n"); // Verifica daca exista argumente suplimentare neasteptate

        // --- Procesare Comenzi ---
        if (strcmp(cmd_token, "start_monitor") == 0) {
            if (arg1 != NULL) { fprintf(stderr, "[Hub] Eroare: 'start_monitor' nu necesita argumente.\n"); continue; }
            if (monitor_is_running) { fprintf(stderr, "[Hub] Eroare: Monitorul deja ruleaza (PID %d).\n", monitor_pid); continue; }

            // Creeaza pipe-ul pentru comunicarea Monitor -> Hub
            if (pipe(pipe_MtoH_fd) == -1) {
                perror("[Hub] Eroare la crearea pipe-ului MtoH");
                continue;
            }

            monitor_pid = fork(); // Creeaza procesul Monitor
            if (monitor_pid < 0) { // Eroare la fork
                perror("[Hub] Eroare la fork pentru monitor");
                close(pipe_MtoH_fd[0]); close(pipe_MtoH_fd[1]); // Inchide pipe-ul
                pipe_MtoH_fd[0] = -1; pipe_MtoH_fd[1] = -1;     // Reseteaza descriptorii
            } else if (monitor_pid == 0) { // Proces copil (Monitor)
                // Monitorul inchide capatul de citire al pipe-ului MtoH
                close(pipe_MtoH_fd[0]);
                // Intra in bucla principala a Monitorului, pasand capatul de scriere al pipe-ului
                monitor_main_loop(pipe_MtoH_fd[1]);
                // monitor_main_loop ar trebui sa se termine cu exit().
                exit(EXIT_FAILURE); // Fallback, in caz ca monitor_main_loop returneaza
            } else { // Proces parinte (Hub)
                // Hub-ul inchide capatul de scriere al pipe-ului MtoH
                close(pipe_MtoH_fd[1]);
                pipe_MtoH_fd[1] = -1; // Marcam ca inchis pentru Hub
                monitor_is_running = 1; // Seteaza flag-ul
                printf("[Hub] Proces monitor pornit cu PID %d. Hub citeste pe fd %d.\n", monitor_pid, pipe_MtoH_fd[0]);
            }
        } else if (strcmp(cmd_token, "stop_monitor") == 0) {
            if (arg1 != NULL) { fprintf(stderr, "[Hub] Eroare: 'stop_monitor' nu necesita argumente.\n"); continue; }
            if (!monitor_is_running) { fprintf(stderr, "[Hub] Eroare: Monitorul nu ruleaza.\n"); continue; }

            printf("[Hub] Trimit SIGTERM monitorului (PID %d).\n", monitor_pid);
            if (kill(monitor_pid, SIGTERM) == -1) { // Trimite semnalul de terminare
                perror("[Hub] Eroare la trimiterea SIGTERM");
                // Daca trimiterea esueaza, resetam starea ca si cum monitorul ar fi cazut
                monitor_is_running = 0; monitor_pid = 0;
                if (pipe_MtoH_fd[0] != -1) {close(pipe_MtoH_fd[0]); pipe_MtoH_fd[0] = -1;}
            } else { // Semnal trimis cu succes
                waiting_for_monitor_stop = 1; // Hub-ul intra in starea de asteptare
                printf("[Hub] Astept terminarea monitorului...\n");
                // Handler-ul SIGCHLD se va ocupa de curatenie cand monitorul se termina.
            }
        } else if (strcmp(cmd_token, "list_hunts") == 0) {
            if (arg1 != NULL) { fprintf(stderr, "[Hub] Eroare: 'list_hunts' nu necesita argumente.\n"); continue; }
            if (!monitor_is_running) { fprintf(stderr, "[Hub] Eroare: Monitorul nu ruleaza.\n"); continue; }
            // Comanda simpla, trimitem doar semnal SIGUSR1 la Monitor
            // printf("[Hub] Trimit cerere catre monitor: list_hunts (SIGUSR1)\n"); // Mesaj de debug
            if (kill(monitor_pid, SIGUSR1) == -1) perror("[Hub] Eroare la trimiterea SIGUSR1");
            // Rezultatele vor fi citite cand Monitorul trimite SIGUSR1 inapoi la Hub (data_ready)
        } else if (strcmp(cmd_token, "list_treasures") == 0) {
            if (arg1 == NULL || arg2 != NULL) { fprintf(stderr, "[Hub] Utilizare: list_treasures <hunt_id>\n"); continue; }
            if (!monitor_is_running) { fprintf(stderr, "[Hub] Eroare: Monitorul nu ruleaza.\n"); continue; }
            // Pentru comenzi cu argumente, scriem in COMMAND_FILE si apoi trimitem SIGUSR2
            FILE *fp_cmd = fopen(COMMAND_FILE, "w");
            if (!fp_cmd) { perror("[Hub] Eroare deschidere fisier comanda"); continue; }
            fprintf(fp_cmd, "list_treasures\n%s\n", arg1); // Scrie tipul comenzii si argumentul
            fclose(fp_cmd);
            // printf("[Hub] Trimit cerere monitor: list_treasures pentru '%s' (SIGUSR2)\n", arg1);
            if (kill(monitor_pid, SIGUSR2) == -1) perror("[Hub] Eroare trimitere SIGUSR2");
        } else if (strcmp(cmd_token, "view_treasure") == 0) {
            if (arg1 == NULL || arg2 == NULL || rest != NULL) { fprintf(stderr, "[Hub] Utilizare: view_treasure <hunt_id> <treasure_id>\n"); continue; }
            // Validare simpla ca treasure_id este un numar pozitiv
            char *endptr_check; errno = 0;
            long id_val = strtol(arg2, &endptr_check, 10);
            if (errno != 0 || *endptr_check != '\0' || endptr_check == arg2 || id_val <= 0) {
                 fprintf(stderr, "[Hub] Eroare: treasure_id invalid. Trebuie sa fie un numar intreg pozitiv.\n"); continue;
            }

            if (!monitor_is_running) { fprintf(stderr, "[Hub] Eroare: Monitorul nu ruleaza.\n"); continue; }
            FILE *fp_cmd = fopen(COMMAND_FILE, "w");
            if (!fp_cmd) { perror("[Hub] Eroare deschidere fisier comanda"); continue; }
            fprintf(fp_cmd, "view_treasure\n%s\n%s\n", arg1, arg2); // Scrie comanda si argumentele
            fclose(fp_cmd);
            // printf("[Hub] Trimit cerere monitor: view_treasure pentru %s:%s (SIGUSR2)\n", arg1, arg2);
            if (kill(monitor_pid, SIGUSR2) == -1) perror("[Hub] Eroare trimitere SIGUSR2");
        } else if (strcmp(cmd_token, "calculate_score") == 0) {
            if (arg1 != NULL) { fprintf(stderr, "[Hub] Eroare: 'calculate_score' nu necesita argumente.\n"); continue; }
            handle_calculate_score(); // Apeleaza functia dedicata
        } else if (strcmp(cmd_token, "exit") == 0) {
            if (arg1 != NULL) { fprintf(stderr, "[Hub] Eroare: 'exit' nu necesita argumente.\n"); continue; }
            if (monitor_is_running) { fprintf(stderr, "[Hub] Eroare: Monitorul (PID %d) inca ruleaza. Folositi 'stop_monitor' intai.\n", monitor_pid); continue; }
            printf("[Hub] Iesire.\n");
            break; // Iese din bucla principala
        } else if (strcmp(cmd_token, "help") == 0) {
            if (arg1 != NULL) { fprintf(stderr, "[Hub] Eroare: 'help' nu necesita argumente.\n"); continue; }
            // Afiseaza mesajul de ajutor
            printf("Comenzi disponibile:\n");
            printf("  start_monitor                - Porneste procesul monitor.\n");
            printf("  list_hunts                   - Cere monitorului sa listeze hunt-urile.\n");
            printf("  list_treasures <hunt_id>     - Cere monitorului sa listeze comori pentru un hunt.\n");
            printf("  view_treasure <h_id> <t_id>  - Cere monitorului sa vada o comoara specifica.\n");
            printf("  calculate_score              - Calculeaza si afiseaza scorurile pentru toate hunt-urile.\n");
            printf("  stop_monitor                 - Opreste monitorul si asteapta terminarea.\n");
            printf("  exit                         - Iese din hub (doar daca monitorul e oprit).\n");
            printf("  help                         - Afiseaza acest mesaj.\n");
        } else { // Comanda necunoscuta
            fprintf(stderr, "[Hub] Eroare: Comanda necunoscuta '%s'. Introduceti 'help'.\n", cmd_token);
        }
    } // Sfarsitul buclei while(1)

    // Curatenie finala la iesirea din Hub
    // Inchide capetele de pipe ramase deschise (daca mai sunt)
    if (pipe_MtoH_fd[0] != -1) close(pipe_MtoH_fd[0]);
    // pipe_MtoH_fd[1] ar trebui sa fie -1 aici daca Hub-ul a functionat corect la start_monitor
    if (pipe_MtoH_fd[1] != -1) close(pipe_MtoH_fd[1]); 
    unlink(COMMAND_FILE); // Sterge fisierul de comanda, daca a ramas
    printf("[Hub] Program terminat.\n");
    return EXIT_SUCCESS;
}
