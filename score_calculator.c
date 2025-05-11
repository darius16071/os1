// score_calculator.c
#define _XOPEN_SOURCE 700 // Pentru diverse functii POSIX, daca sunt necesare
#define _DEFAULT_SOURCE   // Pentru diverse functii POSIX, daca sunt necesare

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>     // Pentru PATH_MAX
#include <errno.h>

// Reutilizam constantele si structurile
// Ideal, acestea ar fi intr-un fisier header comun (.h) inclus de ambele programe.
#define MAX_USERNAME_LEN 50
#define MAX_CLUE_LEN 256
#define TREASURE_FILE_NAME "treasures.bin"
#define MAX_USERS 100 // O limita simpla pentru array-ul de utilizatori unici

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

typedef struct {
    char username[MAX_USERNAME_LEN];
    int total_score;
} UserScore;

int main(int argc, char *argv[]) {
    // Verifica daca a fost furnizat exact un argument (hunt_id)
    if (argc != 2) {
        fprintf(stderr, "Utilizare: %s <hunt_id>\n", argv[0]);
        return EXIT_FAILURE; // Iesire cu eroare
    }
    const char *hunt_id = argv[1]; // Primul argument este hunt_id
    char treasure_file_path[PATH_MAX];

    // Construim calea catre fisierul de comori
    // Presupunem ca directoarele hunt sunt subdirectoare ale directorului curent
    // unde este rulat score_calculator (acesta va fi directorul curent al hub-ului)
    snprintf(treasure_file_path, sizeof(treasure_file_path), "./%s/%s", hunt_id, TREASURE_FILE_NAME);

    // Deschidem fisierul de comori pentru citire
    int fd = open(treasure_file_path, O_RDONLY);
    if (fd == -1) {
        // perror() afiseaza un mesaj de eroare specific sistemului
        perror("Eroare la deschiderea fisierului de comori de catre score_calculator");
        fprintf(stderr, "score_calculator: Nu pot deschide: %s\n", treasure_file_path);
        return EXIT_FAILURE; // Iesire cu eroare
    }

    UserScore scores[MAX_USERS]; // Array pentru a stoca scorurile utilizatorilor
    int num_unique_users = 0;    // Numarul de utilizatori unici gasiti
    Treasure current_treasure;   // Buffer pentru citirea fiecarei comori
    ssize_t bytes_read;

    // Initializam array-ul de scoruri (optional, dar buna practica)
    for(int i=0; i<MAX_USERS; ++i) {
        scores[i].username[0] = '\0'; // Marcam ca slot gol
        scores[i].total_score = 0;
    }

    // Citim comorile din fisier
    while ((bytes_read = read(fd, &current_treasure, sizeof(Treasure))) > 0) {
        if (bytes_read < sizeof(Treasure)) { // Verificam citire partiala
            fprintf(stderr, "score_calculator: Avertisment: Fisierul de comori %s pare corupt.\n", treasure_file_path);
            break; // Oprim procesarea
        }

        // Ignoram comorile fara nume de utilizator (desi validarea din Faza 1 ar trebui sa previna asta)
        if (current_treasure.username[0] == '\0') {
            continue;
        }

        int user_found_idx = -1; // Indexul utilizatorului in array-ul scores
        // Cautam daca utilizatorul curent exista deja in lista noastra de scoruri
        for (int i = 0; i < num_unique_users; i++) {
            if (strcmp(scores[i].username, current_treasure.username) == 0) {
                user_found_idx = i; // Am gasit utilizatorul
                break;
            }
        }

        if (user_found_idx != -1) { // Daca utilizatorul a fost gasit
            scores[user_found_idx].total_score += current_treasure.value; // Adaugam la scorul existent
        } else { // Daca este un utilizator nou
            if (num_unique_users < MAX_USERS) { // Verificam daca mai avem loc in array
                // Copiem numele utilizatorului si setam scorul initial
                strncpy(scores[num_unique_users].username, current_treasure.username, MAX_USERNAME_LEN -1);
                scores[num_unique_users].username[MAX_USERNAME_LEN-1] = '\0'; // Asiguram null-termination
                scores[num_unique_users].total_score = current_treasure.value;
                num_unique_users++; // Incrementam numarul de utilizatori unici
            } else {
                // Am atins limita de utilizatori unici pe care o putem stoca
                fprintf(stderr, "score_calculator: Avertisment: Numarul maxim de utilizatori (%d) atins. Scorul pentru %s nu este complet.\n", MAX_USERS, current_treasure.username);
            }
        }
    }

    // Verificam eroare la ultimul apel read()
    if (bytes_read < 0) {
        perror("score_calculator: Eroare la citirea din fisierul de comori");
    }
    close(fd); // Inchidem fisierul

    // Afisam scorurile calculate pe STDOUT
    // Acest STDOUT va fi redirectat de hub catre un pipe
    if (num_unique_users == 0) {
        // Daca bytes_read a fost 0 (EOF la inceput) sau nu s-au gasit useri valizi
        if (bytes_read == 0 && errno == 0) { // EOF curat, fisier gol sau fara useri
            printf("Nicio comoara cu utilizator valid gasita in hunt-ul '%s' pentru a calcula scoruri.\n", hunt_id);
        }
        // Daca bytes_read < 0, eroarea a fost deja afisata de perror
    } else {
        printf("Scoruri pentru Hunt '%s':\n", hunt_id);
        for (int i = 0; i < num_unique_users; i++) {
            // Formatul output: "username: score"
            printf("%s: %d\n", scores[i].username, scores[i].total_score);
        }
    }

    return EXIT_SUCCESS; // Iesire cu succes
}