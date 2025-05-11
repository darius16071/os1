// treasure_hub.c - Faza 3 Completa cu Citire Pipe Imbunatatita si Corectii Exit
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

// --- Constante ---
#define MAX_USERNAME_LEN 50
#define MAX_CLUE_LEN 256
#define MAX_INPUT_BUFFER 512
#define MAX_ACCUMULATED_BUFFER 8192 // Buffer mai mare pentru acumularea datelor din pipe
#define MAX_PATH_LEN PATH_MAX
#define TREASURE_FILE_NAME "treasures.bin"
#define DIR_PERMS 0755
#define FILE_PERMS 0644
#define SCORE_CALCULATOR_EXEC "./score_calculator"
#define PIPE_DELIMITER "%%END_OF_DATA%%\n" // Delimitator pentru comunicarea prin pipe

// --- Structuri de date ---
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
volatile sig_atomic_t monitor_is_running = 0;
volatile sig_atomic_t waiting_for_monitor_stop = 0;
pid_t monitor_pid = 0;
int pipe_monitor_to_hub[2] = {-1, -1}; // Pipe Monitor -> Hub [0]rd, [1]wr

// --- Flag-uri de Semnal pentru Monitor ---
volatile sig_atomic_t sigusr1_received = 0;
volatile sig_atomic_t sigusr2_received = 0;
volatile sig_atomic_t sigterm_received = 0;

// --- Declaratii Anticipate ---
void monitor_main_loop();
void monitor_list_hunts(int write_fd);
void monitor_list_all_treasures(int write_fd);
int count_treasures_in_hunt(const char *hunt_id);
void list_treasures_for_hunt(int write_fd, const char *hunt_id);
void print_treasure_details_to_pipe(int write_fd, const Treasure *t);
void handle_calculate_score();
int read_from_pipe_until_delimiter(int pipe_fd, const char *delimiter);

// --- Signal Handlers ---
void monitor_sigusr1_handler(int signum) { (void)signum; sigusr1_received = 1; }
void monitor_sigusr2_handler(int signum) { (void)signum; sigusr2_received = 1; }
void monitor_sigterm_handler(int signum) { (void)signum; sigterm_received = 1; }

void hub_sigchld_handler(int signum) {
    (void)signum;
    int status;
    pid_t terminated_pid;
    while ((terminated_pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (terminated_pid == monitor_pid) {
            printf("\n[Hub] Procesul monitor (PID %d) s-a terminat.\n", terminated_pid);
            if (WIFEXITED(status)) {
                printf("[Hub] Monitorul a iesit normal cu status %d.\n", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("[Hub] Monitorul a fost terminat de semnalul %d (%s).\n", WTERMSIG(status), strsignal(WTERMSIG(status)));
            } else {
                printf("[Hub] Monitorul s-a terminat cu un status neobisnuit: %d.\n", status);
            }
            if (pipe_monitor_to_hub[0] != -1) {
                close(pipe_monitor_to_hub[0]);
                pipe_monitor_to_hub[0] = -1;
            }
            monitor_pid = 0;
            monitor_is_running = 0;
            waiting_for_monitor_stop = 0; // FOARTE IMPORTANT: reseteaza flag-ul de asteptare
            printf("> "); // Re-afiseaza prompt-ul DUPA ce starea e actualizata
            fflush(stdout);
        }
    }
    if (terminated_pid == -1 && errno != ECHILD && errno != 0) {
         // perror("[Hub SIGCHLD] Eroare la waitpid in handler"); // Poate fi zgomotos
    }
}

int setup_signal_handler(int signum, void (*handler)(int)) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(signum, &sa, NULL) == -1) {
        char msg[100];
        snprintf(msg, sizeof(msg), "Eroare la configurarea sigaction pentru semnalul %d", signum);
        perror(msg);
        return -1;
    }
    return 0;
}

// --- Functiile Procesului Monitor ---
void monitor_main_loop() {
    printf("[Monitor %d] Pornit si asteapta semnale... Scrie pe fd %d.\n", getpid(), pipe_monitor_to_hub[1]);
    if (setup_signal_handler(SIGUSR1, monitor_sigusr1_handler) == -1 ||
        setup_signal_handler(SIGUSR2, monitor_sigusr2_handler) == -1 ||
        setup_signal_handler(SIGTERM, monitor_sigterm_handler) == -1) {
        fprintf(stderr, "[Monitor %d] Eroare fatala la configurarea handler-elor de semnal. Iesire.\n", getpid());
        if (pipe_monitor_to_hub[1] != -1) close(pipe_monitor_to_hub[1]);
        exit(EXIT_FAILURE);
    }
    while (!sigterm_received) {
        if (sigusr1_received) {
            sigusr1_received = 0;
            // printf("[Monitor %d DEBUG] Primit SIGUSR1: Trimit date pentru list_hunts...\n", getpid());
            monitor_list_hunts(pipe_monitor_to_hub[1]);
        }
        if (sigusr2_received) {
            sigusr2_received = 0;
            // printf("[Monitor %d DEBUG] Primit SIGUSR2: Trimit date pentru list_all_treasures...\n", getpid());
            monitor_list_all_treasures(pipe_monitor_to_hub[1]);
        }
        pause();
    }
    printf("[Monitor %d] SIGTERM primit. Curatenie si iesire...\n", getpid());
    printf("[Monitor %d] Execut task-uri finale (intarziere %d secunde)...\n", getpid(), 2);
    sleep(2);
    if (pipe_monitor_to_hub[1] != -1) {
        // printf("[Monitor %d DEBUG] Inchid capatul de scriere al pipe-ului (fd %d) inainte de exit.\n", getpid(), pipe_monitor_to_hub[1]);
        close(pipe_monitor_to_hub[1]);
        pipe_monitor_to_hub[1] = -1;
    }
    printf("[Monitor %d] Iesire acum.\n", getpid());
    // exit() va fi apelat automat la sfarsitul functiei main a copilului
}

int count_treasures_in_hunt(const char *hunt_id) {
    char treasure_file_path[MAX_PATH_LEN];
    snprintf(treasure_file_path, sizeof(treasure_file_path), "./%s/%s", hunt_id, TREASURE_FILE_NAME);
    int fd = open(treasure_file_path, O_RDONLY);
    if (fd == -1) return 0;
    int count = 0;
    Treasure t;
    while (read(fd, &t, sizeof(Treasure)) == sizeof(Treasure)) count++;
    close(fd);
    return count;
}

void monitor_list_hunts(int write_fd) {
    char buffer[MAX_INPUT_BUFFER * 2];
    int offset = 0;
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "\n--- [Monitor] Hunt-uri Descoperite ---\n");
    DIR *dirp = opendir(".");
    if (!dirp) {
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "[Monitor] Eroare la deschiderea directorului curent (.).\n-------------------------------------\n");
        if (offset > 0) write(write_fd, buffer, offset);
        write(write_fd, PIPE_DELIMITER, strlen(PIPE_DELIMITER));
        return;
    }
    struct dirent *entry;
    struct stat st;
    int hunt_count = 0;
    char path_buffer[MAX_PATH_LEN];
    while ((entry = readdir(dirp)) != NULL) {
        snprintf(path_buffer, sizeof(path_buffer), "./%s", entry->d_name);
        if (stat(path_buffer, &st) == 0) {
            if (S_ISDIR(st.st_mode) && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                snprintf(path_buffer, sizeof(path_buffer), "./%s/%s", entry->d_name, TREASURE_FILE_NAME);
                struct stat treasure_stat;
                 if (stat(path_buffer, &treasure_stat) == 0 && S_ISREG(treasure_stat.st_mode)) {
                     int treasure_count = count_treasures_in_hunt(entry->d_name);
                     offset += snprintf(buffer + offset, sizeof(buffer) - offset, "  Hunt ID: %-20s (%d comori)\n", entry->d_name, treasure_count);
                     hunt_count++;
                     if (sizeof(buffer) - offset < 200) {
                         if(offset > 0) write(write_fd, buffer, offset); // Scrie ce s-a acumulat
                         offset = 0; // Reseteaza offset
                     }
                 }
            }
        }
    }
    closedir(dirp);
    if (hunt_count == 0) {
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "  (Niciun hunt valid gasit)\n");
    }
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "-------------------------------------\n");
    if (offset > 0) write(write_fd, buffer, offset);
    write(write_fd, PIPE_DELIMITER, strlen(PIPE_DELIMITER));
}

void print_treasure_details_to_pipe(int write_fd, const Treasure *t) {
    if (!t) return;
    char buffer[MAX_INPUT_BUFFER * 2]; // Suficient pentru o comoara
    int len = snprintf(buffer, sizeof(buffer),
             "    ID:          %d\n"
             "    Utilizator:  %s\n"
             "    GPS (Lat,Lon): (%.6f, %.6f)\n"
             "    Indiciu:     \"%s\"\n"
             "    Valoare:     %d\n"
             "    ----\n",
             t->id, t->username, t->coordinates.latitude, t->coordinates.longitude,
             t->clue, t->value);
    if (len > 0) {
        write(write_fd, buffer, len);
    }
}

void list_treasures_for_hunt(int write_fd, const char *hunt_id) {
    char treasure_file_path[MAX_PATH_LEN];
    char buffer[MAX_INPUT_BUFFER];
    int offset = 0;
    snprintf(treasure_file_path, sizeof(treasure_file_path), "./%s/%s", hunt_id, TREASURE_FILE_NAME);
    int fd = open(treasure_file_path, O_RDONLY);

    // Trimite antetul hunt-ului indiferent daca fisierul e gasit sau nu
    offset = snprintf(buffer, sizeof(buffer), "--- [Monitor] Comori in Hunt: %s ---\n", hunt_id);
    if (offset > 0) write(write_fd, buffer, offset);
    offset = 0; // Reset

    if (fd == -1) {
         if (errno != ENOENT) { // Doar daca nu e "File not found"
            offset = snprintf(buffer, sizeof(buffer), "[Monitor] Avertisment: Nu pot deschide %s: %s\n",
                     TREASURE_FILE_NAME, strerror(errno));
         }
         offset += snprintf(buffer + offset, sizeof(buffer) - offset, "    (Fisierul de comori nu a putut fi accesat sau este gol)\n    ----\n");
         if (offset > 0) write(write_fd, buffer, offset);
         return;
    }

    Treasure current_treasure;
    ssize_t bytes_read;
    int count = 0;
    while ((bytes_read = read(fd, &current_treasure, sizeof(Treasure))) > 0) {
        if (bytes_read < sizeof(Treasure)) {
            offset = snprintf(buffer, sizeof(buffer),"[Monitor] Avertisment: Fisierul '%s' pare corupt (citire partiala).\n", treasure_file_path);
            if (offset > 0) write(write_fd, buffer, offset);
            break;
        }
        count++;
        print_treasure_details_to_pipe(write_fd, &current_treasure);
    }
    if (bytes_read < 0) {
        offset = snprintf(buffer, sizeof(buffer),"[Monitor] Eroare la citirea fisierului '%s': %s\n", treasure_file_path, strerror(errno));
        if (offset > 0) write(write_fd, buffer, offset);
    }
    if (count == 0) { // Daca fisierul a fost deschis dar nu s-au gasit comori
        offset = snprintf(buffer, sizeof(buffer), "    (Nicio comoara gasita in acest hunt)\n    ----\n");
        if (offset > 0) write(write_fd, buffer, offset);
    }
    close(fd);
}

void monitor_list_all_treasures(int write_fd) {
     char buffer[MAX_INPUT_BUFFER];
     int offset = 0;
     offset = snprintf(buffer, sizeof(buffer), "\n--- [Monitor] Listare Toate Comorile (Actiune SIGUSR2) ---\n");
     if (offset > 0) write(write_fd, buffer, offset);

     DIR *dirp = opendir(".");
     if (!dirp) {
         offset = snprintf(buffer, sizeof(buffer),"[Monitor] Eroare la deschiderea directorului curent (.).\n--------------------------------------------------------\n");
         if (offset > 0) write(write_fd, buffer, offset);
         write(write_fd, PIPE_DELIMITER, strlen(PIPE_DELIMITER));
         return;
     }
     struct dirent *entry;
     struct stat st;
     int hunts_processed = 0;
     char path_buffer[MAX_PATH_LEN];
     while ((entry = readdir(dirp)) != NULL) {
         snprintf(path_buffer, sizeof(path_buffer), "./%s", entry->d_name);
         if (stat(path_buffer, &st) == 0) {
             if (S_ISDIR(st.st_mode) && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                 snprintf(path_buffer, sizeof(path_buffer), "./%s/%s", entry->d_name, TREASURE_FILE_NAME);
                 struct stat treasure_stat;
                 if (stat(path_buffer, &treasure_stat) == 0 && S_ISREG(treasure_stat.st_mode)) {
                     list_treasures_for_hunt(write_fd, entry->d_name);
                     hunts_processed++;
                 }
             }
         }
     }
     closedir(dirp);
     offset = 0;
     if (hunts_processed == 0) {
         offset += snprintf(buffer + offset, sizeof(buffer) - offset,"  (Niciun hunt valid gasit pentru a lista comori)\n");
     }
     offset += snprintf(buffer + offset, sizeof(buffer) - offset,"--------------------------------------------------------\n");
     if (offset > 0) write(write_fd, buffer, offset);
     write(write_fd, PIPE_DELIMITER, strlen(PIPE_DELIMITER));
}

int read_from_pipe_until_delimiter(int pipe_fd, const char *delimiter) {
    char read_buf[1024];
    char accumulated_buf[MAX_ACCUMULATED_BUFFER];
    accumulated_buf[0] = '\0';
    size_t accumulated_len = 0;
    ssize_t n_read;
    int delimiter_found = 0;
    int ret_val = 1; // Presupunem ca nu gasim delimitatorul initial

    while ((n_read = read(pipe_fd, read_buf, sizeof(read_buf) - 1)) > 0) {
        read_buf[n_read] = '\0';
        if (accumulated_len + n_read < MAX_ACCUMULATED_BUFFER) {
            strcat(accumulated_buf, read_buf);
            accumulated_len += n_read;
        } else {
            printf("%s", accumulated_buf); // Afisam ce s-a acumulat pana la depasire
            accumulated_buf[0] = '\0'; // Resetam
            accumulated_len = 0;
            if (n_read < MAX_ACCUMULATED_BUFFER) { // Copiem noul buffer daca incape
                 strcpy(accumulated_buf, read_buf);
                 accumulated_len = n_read;
            }
            fprintf(stderr, "\n[Hub] Avertisment: Bufferul intern de acumulare a fost depasit. Outputul poate fi fragmentat.\n");
        }
        char *eof_marker = strstr(accumulated_buf, delimiter);
        if (eof_marker != NULL) {
            *eof_marker = '\0';
            printf("%s", accumulated_buf);
            // Gestionam ce e dupa delimitator (daca exista ceva in acelasi read)
            char* remaining_data_start = eof_marker + strlen(delimiter);
            if (*remaining_data_start != '\0') {
                // Mutam datele ramase la inceputul bufferului acumulat
                memmove(accumulated_buf, remaining_data_start, strlen(remaining_data_start) + 1);
                accumulated_len = strlen(accumulated_buf);
                 // printf("[Hub DEBUG] Date ramase in buffer dupa delimitator: [[%s]]\n", accumulated_buf);
            } else {
                accumulated_buf[0] = '\0';
                accumulated_len = 0;
            }
            delimiter_found = 1;
            ret_val = 0;
            break;
        }
    }

    if (accumulated_len > 0 && !delimiter_found) { // Afisam ce a mai ramas daca nu am gasit delimitatorul
        printf("%s", accumulated_buf);
    }

    if (n_read == 0) { // EOF
        // printf("[Hub DEBUG] EOF atins in pipe. Delimiter gasit: %d\n", delimiter_found);
        ret_val = delimiter_found ? 0 : 0; // EOF este un sfarsit valid
    } else if (n_read < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("[Hub] Eroare la citirea din pipe-ul Monitor->Hub");
            ret_val = -1;
        } else if (!delimiter_found) {
             // Pipe non-blocant si nu sunt date acum, dar nici delimitatorul
             // printf("[Hub DEBUG] Pipe non-blocant, nu sunt date, delimitator negasit.\n");
        }
    }
    return ret_val;
}

void handle_calculate_score() {
    printf("[Hub] Calculare scoruri pentru toate hunt-urile...\n");
    DIR *dirp = opendir(".");
    if (!dirp) {
        perror("[Hub] Eroare la deschiderea directorului curent pentru calculate_score");
        return;
    }
    struct dirent *entry;
    struct stat st_hunt;
    char hunt_path_buffer[MAX_PATH_LEN];
    int hunts_found_for_scoring = 0;
    while ((entry = readdir(dirp)) != NULL) {
        snprintf(hunt_path_buffer, sizeof(hunt_path_buffer), "./%s", entry->d_name);
        if (stat(hunt_path_buffer, &st_hunt) == 0) {
            if (S_ISDIR(st_hunt.st_mode) && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                char treasure_check_path[MAX_PATH_LEN];
                snprintf(treasure_check_path, sizeof(treasure_check_path), "%s/%s", hunt_path_buffer, TREASURE_FILE_NAME);
                struct stat st_treasure;
                if (stat(treasure_check_path, &st_treasure) == 0 && S_ISREG(st_treasure.st_mode)) {
                    hunts_found_for_scoring++;
                    printf("\n[Hub] Procesare hunt: %s\n", entry->d_name);
                    int score_pipe_fd[2];
                    if (pipe(score_pipe_fd) == -1) {
                        perror("[Hub] Eroare la crearea pipe-ului pentru score_calculator");
                        continue;
                    }
                    pid_t calculator_pid = fork();
                    if (calculator_pid < 0) {
                        perror("[Hub] Eroare la fork pentru score_calculator");
                        close(score_pipe_fd[0]); close(score_pipe_fd[1]);
                        continue;
                    } else if (calculator_pid == 0) { // Copil (Lansator score_calculator)
                        signal(SIGCHLD, SIG_DFL);
                        if(pipe_monitor_to_hub[0] != -1) close(pipe_monitor_to_hub[0]);
                        if(pipe_monitor_to_hub[1] != -1) close(pipe_monitor_to_hub[1]);
                        close(score_pipe_fd[0]);
                        if (dup2(score_pipe_fd[1], STDOUT_FILENO) == -1) {
                            perror("[Hub-Copil] Eroare la dup2 pentru stdout");
                            close(score_pipe_fd[1]);
                            exit(EXIT_FAILURE);
                        }
                        close(score_pipe_fd[1]);
                        execlp(SCORE_CALCULATOR_EXEC, "score_calculator", entry->d_name, (char *)NULL);
                        fprintf(stderr, "[Hub-Copil] Eroare la execlp pentru %s: %s\n", SCORE_CALCULATOR_EXEC, strerror(errno));
                        exit(EXIT_FAILURE);
                    } else { // Parinte (Hub)
                        close(score_pipe_fd[1]);
                        char score_buffer[2048];
                        ssize_t n_read_score;
                        // Citim tot output-ul de la score_calculator
                        while ((n_read_score = read(score_pipe_fd[0], score_buffer, sizeof(score_buffer) - 1)) > 0) {
                            score_buffer[n_read_score] = '\0';
                            printf("%s", score_buffer);
                        }
                        if (n_read_score < 0) {
                            perror("[Hub] Eroare la citirea din pipe-ul de la score_calculator");
                        }
                        close(score_pipe_fd[0]);
                        int calculator_status;
                        waitpid(calculator_pid, &calculator_status, 0);
                        if (WIFEXITED(calculator_status)) {
                            if(WEXITSTATUS(calculator_status) != 0) {
                                fprintf(stderr, "[Hub] score_calculator pentru hunt %s (PID %d) s-a terminat cu eroare (status %d).\n",
                                        entry->d_name, calculator_pid, WEXITSTATUS(calculator_status));
                            }
                        } else if (WIFSIGNALED(calculator_status)) {
                            fprintf(stderr, "[Hub] score_calculator pentru hunt %s (PID %d) a fost terminat de semnalul %d.\n",
                                    entry->d_name, calculator_pid, WTERMSIG(calculator_status));
                        }
                    }
                }
            }
        }
    }
    closedir(dirp);
    if (hunts_found_for_scoring == 0) {
        printf("[Hub] Nu s-au gasit hunt-uri valide pentru calcularea scorurilor.\n");
    }
    printf("[Hub] Calculare scoruri finalizata.\n");
}

// --- Functia Principala a Treasure Hub ---
int main() {
    char command_buffer[MAX_INPUT_BUFFER];
    char *cmd_token, *arg1 = NULL, *arg2 = NULL;

    printf("Interfata Treasure Hub. Introduceti 'help' pentru comenzi.\n");
    if (setup_signal_handler(SIGCHLD, hub_sigchld_handler) == -1) return EXIT_FAILURE;
    pipe_monitor_to_hub[0] = -1; pipe_monitor_to_hub[1] = -1;

    while (1) {
        if (waiting_for_monitor_stop) {
            // Asteptam ca SIGCHLD handler sa reseteze waiting_for_monitor_stop
            // Dupa ce handler-ul ruleaza si reseteaza flag-ul, pause() va fi intrerupt
            // si bucla va continua, afisand prompt-ul mai jos.
            pause();
            // Daca pause() a fost intrerupt de alt semnal si waiting_for_monitor_stop e inca 1,
            // vom reintra in pause() la urmatoarea iteratie a `while(1)` prin `continue`.
            // Daca waiting_for_monitor_stop a devenit 0, vom iesi din acest if.
            if (waiting_for_monitor_stop) { // Re-verificam flag-ul dupa pause
                continue; // Inca asteptam, reia bucla si apeleaza pause din nou
            }
            // Daca am ajuns aici, waiting_for_monitor_stop este 0, deci afisam prompt-ul normal
        }

        printf("> ");
        fflush(stdout);

        if (fgets(command_buffer, sizeof(command_buffer), stdin) == NULL) {
            if (feof(stdin)) {
                printf("\n[Hub] EOF detectat. Iesire.\n");
                if (monitor_is_running && monitor_pid != 0) {
                    printf("[Hub] Trimit SIGTERM monitorului (PID %d) la iesire.\n", monitor_pid);
                    if (pipe_monitor_to_hub[0] != -1) { close(pipe_monitor_to_hub[0]); pipe_monitor_to_hub[0] = -1; }
                    kill(monitor_pid, SIGTERM);
                }
                break;
            } else {
                if (errno == EINTR) { // Daca fgets a fost intrerupt de un semnal
                    clearerr(stdin);  // Reseteaza starea de eroare a stdin
                    printf("\n[Hub] Citire intrerupta de semnal, incercati din nou.\n"); // Mesaj pt utilizator
                    // Prompt-ul va fi reafisat la urmatoarea iteratie a buclei
                    continue;
                }
                perror("[Hub] Eroare la citirea comenzii");
                // Pentru alte erori fgets, poate ar trebui sa iesim, dar deocamdata continuam
                continue;
            }
        }
        command_buffer[strcspn(command_buffer, "\n")] = 0;
        cmd_token = strtok(command_buffer, " \t\n");
        if (cmd_token == NULL) continue;
        arg1 = strtok(NULL, " \t\n");
        arg2 = (arg1 != NULL) ? strtok(NULL, " \t\n") : NULL;

        if (strcmp(cmd_token, "start_monitor") == 0) {
            if (arg1 != NULL) { fprintf(stderr, "[Hub] Eroare: 'start_monitor' nu necesita argumente.\n"); continue; }
            if (monitor_is_running) { fprintf(stderr, "[Hub] Eroare: Monitorul deja ruleaza (PID %d).\n", monitor_pid); }
            else {
                if (pipe(pipe_monitor_to_hub) == -1) { perror("[Hub] Eroare la crearea pipe-ului"); continue; }
                monitor_pid = fork();
                if (monitor_pid < 0) {
                    perror("[Hub] Eroare: fork");
                    monitor_pid = 0;
                    close(pipe_monitor_to_hub[0]); pipe_monitor_to_hub[0] = -1;
                    close(pipe_monitor_to_hub[1]); pipe_monitor_to_hub[1] = -1;
                } else if (monitor_pid == 0) {
                    signal(SIGCHLD, SIG_DFL);
                    close(pipe_monitor_to_hub[0]); pipe_monitor_to_hub[0] = -1;
                    monitor_main_loop();
                    // Monitorul inchide pipe_monitor_to_hub[1] inainte de a iesi din monitor_main_loop
                    exit(EXIT_SUCCESS);
                } else {
                    close(pipe_monitor_to_hub[1]); pipe_monitor_to_hub[1] = -1;
                    monitor_is_running = 1;
                    printf("[Hub] Proces monitor pornit cu PID %d. Hub citeste pe fd %d.\n", monitor_pid, pipe_monitor_to_hub[0]);
                }
            }
        } else if (strcmp(cmd_token, "stop_monitor") == 0) {
            if (arg1 != NULL) { fprintf(stderr, "[Hub] Eroare: 'stop_monitor' nu necesita argumente.\n"); continue; }
            if (!monitor_is_running || monitor_pid == 0) {
                fprintf(stderr, "[Hub] Eroare: Monitorul nu ruleaza.\n");
            } else {
                printf("[Hub] Trimit SIGTERM monitorului (PID %d).\n", monitor_pid);
                if (kill(monitor_pid, SIGTERM) == -1) {
                    perror("[Hub] Eroare la trimiterea SIGTERM");
                    if (errno == ESRCH) { // Procesul nu exista (poate s-a oprit intre timp)
                        monitor_is_running = 0; monitor_pid = 0;
                        if(pipe_monitor_to_hub[0] != -1) {close(pipe_monitor_to_hub[0]); pipe_monitor_to_hub[0] = -1;}
                    }
                } else {
                    waiting_for_monitor_stop = 1;
                    printf("[Hub] Astept terminarea monitorului... (comenzi blocate)\n");
                }
            }
        } else if (strcmp(cmd_token, "list_hunts") == 0) {
            if (arg1 != NULL) { fprintf(stderr, "[Hub] Eroare: 'list_hunts' nu necesita argumente.\n"); continue; }
            if (!monitor_is_running || pipe_monitor_to_hub[0] == -1) {
                 fprintf(stderr, "[Hub] Eroare: Monitorul nu ruleaza sau pipe-ul nu este initializat.\n");
            } else {
                if (kill(monitor_pid, SIGUSR1) == -1) { perror("[Hub] Eroare la trimiterea SIGUSR1"); }
                else {
                    printf("[Hub] Astept raspuns de la monitor pentru list_hunts...\n");
                    printf("\n--- Raspuns Monitor (list_hunts) ---\n");
                    if (read_from_pipe_until_delimiter(pipe_monitor_to_hub[0], PIPE_DELIMITER) != 0) {
                        // fprintf(stderr, "[Hub] Avertisment: Citirea de la monitor pentru list_hunts poate fi incompleta sau a esuat.\n");
                    }
                    printf("--- Sfarsit Raspuns Monitor ---\n");
                }
            }
        } else if (strcmp(cmd_token, "list_treasures") == 0 || strcmp(cmd_token, "view_treasure") == 0) {
            const char* action_name = cmd_token;
            int expected_args = (strcmp(action_name, "list_treasures") == 0) ? 1 : 2;
            int args_ok = (expected_args == 1 && arg1 != NULL && arg2 == NULL) ||
                          (expected_args == 2 && arg1 != NULL && arg2 != NULL);
            if (!args_ok) {
                if (expected_args == 1) fprintf(stderr, "[Hub] Utilizare: list_treasures <hunt_id>\n");
                else fprintf(stderr, "[Hub] Utilizare: view_treasure <hunt_id> <treasure_id>\n");
                continue;
            }
            if (!monitor_is_running || pipe_monitor_to_hub[0] == -1) {
                 fprintf(stderr, "[Hub] Eroare: Monitorul nu ruleaza sau pipe-ul nu este initializat.\n");
            } else {
                if (kill(monitor_pid, SIGUSR2) == -1) { perror("[Hub] Eroare la trimiterea SIGUSR2"); }
                else {
                    printf("[Hub] Astept raspuns de la monitor pentru %s...\n", action_name);
                    printf("\n--- Raspuns Monitor (%s) ---\n", action_name);
                    if (read_from_pipe_until_delimiter(pipe_monitor_to_hub[0], PIPE_DELIMITER) != 0) {
                        // fprintf(stderr, "[Hub] Avertisment: Citirea de la monitor pentru %s poate fi incompleta sau a esuat.\n", action_name);
                    }
                    printf("--- Sfarsit Raspuns Monitor ---\n");
                }
            }
        } else if (strcmp(cmd_token, "calculate_score") == 0) {
            if (arg1 != NULL) { fprintf(stderr, "[Hub] Eroare: 'calculate_score' nu necesita argumente.\n"); continue; }
            handle_calculate_score();
        } else if (strcmp(cmd_token, "exit") == 0) {
            if (arg1 != NULL) { fprintf(stderr, "[Hub] Eroare: 'exit' nu necesita argumente.\n"); continue; }
            if (monitor_is_running || waiting_for_monitor_stop) {
                fprintf(stderr, "[Hub] Eroare: Monitorul (PID %d) inca ruleaza sau este in curs de oprire. Folositi 'stop_monitor' si asteptati.\n", monitor_pid);
            } else {
                printf("[Hub] Iesire.\n");
                break;
            }
        } else if (strcmp(cmd_token, "help") == 0) {
            if (arg1 != NULL) { fprintf(stderr, "[Hub] Eroare: 'help' nu necesita argumente.\n"); continue; }
            printf("Comenzi disponibile:\n");
            printf("  start_monitor                - Porneste procesul monitor.\n");
            printf("  list_hunts                   - Cere monitorului sa listeze hunt-urile.\n");
            printf("  list_treasures <hunt_id>     - Cere monitorului sa listeze comori (afiseaza toate).\n");
            printf("  view_treasure <h_id> <t_id>  - Cere monitorului sa vada o comoara (afiseaza toate).\n");
            printf("  calculate_score              - Calculeaza si afiseaza scorurile utilizatorilor per hunt.\n");
            printf("  stop_monitor                 - Opreste monitorul si asteapta terminarea.\n");
            printf("  exit                         - Iese din hub (doar daca monitorul e oprit).\n");
            printf("  help                         - Afiseaza acest mesaj.\n");
        } else {
            fprintf(stderr, "[Hub] Eroare: Comanda necunoscuta '%s'. Introduceti 'help'.\n", cmd_token);
        }
    }
    printf("[Hub] Program terminat.\n");
    return EXIT_SUCCESS;
}