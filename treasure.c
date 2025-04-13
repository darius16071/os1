
#define _XOPEN_SOURCE 700 // Necesare pentru diverse funcții POSIX
#define _DEFAULT_SOURCE   // Pentru ctime etc.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>      // Pentru open() și flag-uri O_*
#include <sys/stat.h>   // Pentru stat(), mkdir(), mode constants
#include <sys/types.h>
#include <errno.h>      // Pentru errno și perror()
#include <time.h>       // Pentru ctime(), time()
#include <limits.h>     // Pentru PATH_MAX
#include <dirent.h>     // Pentru opendir() etc. (folosit în remove_hunt)
#include <ctype.h>      // Pentru isspace() în validarea inputului

// --- Constante ---
#define MAX_USERNAME_LEN 50 //// Lungimea maximă a numelui de utilizator
#define MAX_CLUE_LEN 256    //lungimea maximă a indiciului
#define MAX_INPUT_BUFFER 512 // Buffer pentru citirea liniilor cu fgets
#define MAX_PATH_LEN PATH_MAX // Folosește constanta sistemului pentru lungimea maximă a căii

// Numele de fișiere și directoare conform specificației 
#define TREASURE_FILE_NAME "treasures.bin" // Fișier binar
#define LOG_FILE_NAME "logged_hunt.txt"    // Numele fișierului de log
#define LOG_SYMLINK_PREFIX "logged_hunt-"  // Prefixul pentru legătura simbolică

// Permisiuni implicite mai sigure
#define DIR_PERMS 0755  // rwxr-xr-x
#define FILE_PERMS 0644 // rw-r--r--

// --- Structuri de date ---
typedef struct {
    float latitude;     
    float longitude;    
} GPSCoordinates;       

typedef struct {
    int id;             // Identificator unic (numeric) al comorii în cadrul hunt-ului
    char username[MAX_USERNAME_LEN]; // Numele utilizatorului care a adăugat comoara
    GPSCoordinates coordinates; // Coordonatele GPS (folosind structura de mai sus)
    char clue[MAX_CLUE_LEN];     // Textul indiciului
    int value;                   // Valoarea (numerică) a comorii
} Treasure; // Structura principală pentru o înregistrare de comoară

// --- Prototypes Funcții ---
void print_usage(const char *prog_name); // Afișează instrucțiunile de utilizare
// Funcții pentru construirea căilor
int get_hunt_path(char *buffer, size_t size, const char *hunt_id);
int get_treasure_file_path(char *buffer, size_t size, const char *hunt_id);
int get_log_file_path(char *buffer, size_t size, const char *hunt_id);
// Funcții pentru symlink și logare
int create_log_symlink(const char *hunt_id);
int log_operation(const char *hunt_id, const char *operation_details);
// Funcții de validare și căutare
int validate_treasure_data(const Treasure *t);
int check_id_exists(const char *hunt_id, int treasure_id);
// Funcții pentru interacțiunea cu utilizatorul și afișare
int prompt_for_treasure_details(Treasure *t, const char *hunt_id);
void print_treasure(const Treasure *t);

// Handler pentru comenzi (returnează 0 la succes, -1 la eroare)
int handle_add(const char *hunt_id);
int handle_list(const char *hunt_id);
int handle_view(const char *hunt_id, int treasure_id); // ID ca int
int handle_remove_treasure(const char *hunt_id, int treasure_id); // ID ca int
int handle_remove_hunt(const char *hunt_id);

// --- Funcții Ajutătoare ---

void print_usage(const char *prog_name) {
    fprintf(stderr, "Utilizare:\n"); // Afișează pe stderr (eroarea standard)
    // Afișează formatul fiecărei comenzi valide
    fprintf(stderr, "  %s add <hunt_id>\n", prog_name);
    fprintf(stderr, "  %s list <hunt_id>\n", prog_name);
    fprintf(stderr, "  %s view <hunt_id> <treasure_id>\n", prog_name);
    fprintf(stderr, "  %s remove_treasure <hunt_id> <treasure_id>\n", prog_name);
    fprintf(stderr, "  %s remove_hunt <hunt_id>\n", prog_name);
    fprintf(stderr, "\nArgumente:\n");
    // Descrie argumentele
    fprintf(stderr, "  <hunt_id>: Numele hunt-ului (director).\n");
    fprintf(stderr, "  <treasure_id>: Identificator numeric unic pentru o comoară.\n");
    fprintf(stderr, "\nExemplu:\n");
    // Oferă un exemplu concret
    fprintf(stderr, "  %s add vanatoare1\n", prog_name);
    fprintf(stderr, "  %s view vanatoare1\n", prog_name);
}


/*

Funcțiile get_*_path: Acestea sunt funcții utilitare pentru a construi în mod sigur căile complete către directorul hunt-ului,
 fișierul de comori și fișierul de log, pe baza hunt_id-ului furnizat. Folosesc snprintf pentru a preveni depășirea bufferului (buffer overflow)
  și verifică rezultatul pentru a se asigura că întreaga cale a încăput în bufferul buffer de dimensiune size.
 Returnează 0 la succes și -1 la eroare.
*/

// Construiește calea către directorul hunt-ului (în directorul curent)
int get_hunt_path(char *buffer, size_t size, const char *hunt_id) {
    // snprintf scrie formatat în 'buffer', maxim 'size' octeți, prevenind overflow-ul.
    // Formatul "./%s" înseamnă directorul hunt_id în directorul curent.
    int n = snprintf(buffer, size, "./%s", hunt_id);
    // Verifică dacă snprintf a returnat eroare (n<0) sau dacă bufferul a fost prea mic (n>=size)
    if (n < 0 || (size_t)n >= size) {
        fprintf(stderr, "Eroare: Hunt ID '%s' generează o cale prea lungă.\n", hunt_id);
        return -1; // Returnează eroare
    }
    return 0; // Returnează succes
}

// Construiește calea către fișierul de comori
int get_treasure_file_path(char *buffer, size_t size, const char *hunt_id) {
    // Similar, construiește calea "<director_hunt>/treasures.bin"
    int n = snprintf(buffer, size, "./%s/%s", hunt_id, TREASURE_FILE_NAME);
    if (n < 0 || (size_t)n >= size) {
        fprintf(stderr, "Eroare: Calea pentru fișierul de comori din hunt '%s' este prea lungă.\n", hunt_id);
        return -1;
    }
    return 0;
}

// Construiește calea către fișierul de log
int get_log_file_path(char *buffer, size_t size, const char *hunt_id) {
    // Similar, construiește calea "<director_hunt>/logged_hunt.txt"
    int n = snprintf(buffer, size, "./%s/%s", hunt_id, LOG_FILE_NAME);
    if (n < 0 || (size_t)n >= size) {
        fprintf(stderr, "Eroare: Calea pentru fișierul de log din hunt '%s' este prea lungă.\n", hunt_id);
        return -1;
    }
    return 0;
}


/*
create_log_symlink: Această funcție gestionează crearea legăturii simbolice (symlink) în directorul curent, care pointează către fișierul logged_hunt.txt din directorul hunt-ului specific.
Construiește calea unde va fi symlink-ul (ex: ./logged_hunt-hunt1).
Construiește calea relativă către țintă (ex: hunt1/logged_hunt.txt). Folosirea căii relative este bună practică aici.
Folosește unlink pentru a șterge un eventual symlink vechi cu același nume.
Folosește apelul de sistem symlink() pentru a crea legătura.
Verifică erorile.
*/

// Creează legătura simbolică în directorul curent
int create_log_symlink(const char *hunt_id) {
    char log_file_path[MAX_PATH_LEN];       // Calea către fișierul țintă (log)
    char symlink_path[MAX_PATH_LEN];        // Calea unde va fi creat symlink-ul
    char target_path_relative[MAX_PATH_LEN + 10]; // Calea țintă, relativă la symlink

    // Obținem calea completă a fișierului de log
    if (get_log_file_path(log_file_path, sizeof(log_file_path), hunt_id) != 0) {
        return -1; // Eroare deja afișată
    }

    // Construim numele symlink-ului (ex: ./logged_hunt-vanatoare1)
    int n = snprintf(symlink_path, sizeof(symlink_path), "./%s%s", LOG_SYMLINK_PREFIX, hunt_id);
    if (n < 0 || (size_t)n >= sizeof(symlink_path)) { /* ... eroare ... */ return -1; }

    // Construim calea țintă RELATIVĂ la directorul curent (unde e symlink-ul)
    // (ex: vanatoare1/logged_hunt.txt)
    n = snprintf(target_path_relative, sizeof(target_path_relative), "%s/%s", hunt_id, LOG_FILE_NAME);
     if (n < 0 || (size_t)n >= sizeof(target_path_relative)) { /* ... eroare ... */ return -1; }

    // Ștergem symlink-ul vechi, dacă există. Ignorăm eroarea dacă nu există (ENOENT).
    // Asta asigură că putem actualiza link-ul.
    unlink(symlink_path);

    // Creăm symlink-ul folosind apelul de sistem symlink(target, linkpath)
    if (symlink(target_path_relative, symlink_path) == -1) {
        perror("Eroare la crearea legăturii simbolice"); // Afișează eroarea sistemului
        fprintf(stderr, "Eșec la legarea '%s' -> '%s'\n", symlink_path, target_path_relative);
        return -1; // Eroare
    }
    return 0; // Succes
}


/*
log_operation: Scrie un mesaj (cu timestamp) în fișierul logged_hunt.txt al hunt-ului specificat.
Verifică întâi dacă directorul hunt-ului există folosind stat. Dacă nu există (relevant la remove_hunt), nu încearcă să logheze.
Folosește fopen cu modul "at" (append text) pentru a deschide/crea fișierul de log. Este convenabil pentru fișiere text simple.
Obține timestamp-ul curent folosind time, localtime, strftime.
Scrie linia formatată în fișier folosind fprintf.
Verifică erorile cu ferror și închide fișierul cu fclose.
Important: Apelează create_log_symlink pentru a se asigura că symlink-ul este mereu corect după o operație logată.
*/

int log_operation(const char *hunt_id, const char *operation_details) {
    if (!operation_details) return -1; // Verificare parametru null

    char log_file_path[MAX_PATH_LEN];
    char hunt_path[MAX_PATH_LEN];
    FILE *log_fp = NULL; // Pointer de fișier din stdio

    // Verificăm dacă directorul hunt există folosind stat()
    if (get_hunt_path(hunt_path, sizeof(hunt_path), hunt_id) != 0) return -1;
    struct stat st; // Structură pentru a stoca informații despre fișier/director
    if (stat(hunt_path, &st) == -1) { // Încearcă să obțină informații
        if (errno == ENOENT) return 0; // Dacă nu există (ENOENT), nu logăm (ex: la remove_hunt)
        else {
            perror("Avertisment: Nu se poate accesa directorul hunt pentru logging");
            return -1; // Altă eroare stat()
        }
    }
    if (!S_ISDIR(st.st_mode)) return -1; // Verifică dacă e director

    // Obținem calea fișierului de log
    if (get_log_file_path(log_file_path, sizeof(log_file_path), hunt_id) != 0) return -1;

    // Deschidem fișierul de log cu fopen în mod "at" (append text)
    // Creează fișierul dacă nu există.
    log_fp = fopen(log_file_path, "at");
    if (!log_fp) {
        perror("Eroare la deschiderea fișierului de log pentru append");
        fprintf(stderr, "Cale fișier log: %s\n", log_file_path);
        return -1;
    }

    // Obținem data și ora curentă
    time_t now = time(NULL);                // Timpul curent (secunde de la Epoch)
    struct tm *local_time = localtime(&now); // Converteste în structura tm locală
    char timestamp[64];                      // Buffer pentru timestamp formatat
    // Formatează timpul în format YYYY-MM-DD HH:MM:SS
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", local_time);

    // Scriem intrarea formatată (timestamp + mesaj) în fișierul de log
    fprintf(log_fp, "[%s] %s\n", timestamp, operation_details);

    // Verificăm dacă au apărut erori în timpul operațiilor fprintf
    if (ferror(log_fp)) {
        fprintf(stderr, "Avertisment: Eroare la scrierea în fișierul de log.\n");
    }
    // Închidem fișierul de log
    if (fclose(log_fp) == EOF) {
        perror("Avertisment: Eroare la închiderea fișierului de log");
    }

    // Asigurăm (re)crearea symlink-ului după fiecare operație logată
    if (create_log_symlink(hunt_id) != 0) {
        fprintf(stderr, "Avertisment: Eșec la crearea/actualizarea symlink-ului de log pentru hunt '%s'.\n", hunt_id);
    }

    return 0; // Succes (logging-ul s-a efectuat, chiar dacă au fost avertismente minore)
}

/*
validate_treasure_data: Efectuează verificări simple asupra datelor dintr-o structură Treasure înainte de a o scrie în fișier. 
Verifică dacă ID-ul este pozitiv și dacă username-ul și indiciul nu sunt goale. Returnează 1 dacă datele sunt valide, 0 altfel.
*/

// Validare de bază pentru datele comorii
int validate_treasure_data(const Treasure *t) {
    if (!t) return 0; // Verificare pointer null
    if (t->id <= 0) { // ID-ul trebuie să fie un întreg pozitiv
         fprintf(stderr, "Eroare: ID-ul comorii trebuie să fie un număr pozitiv.\n");
         return 0; // Invalid
    }
    if (t->username[0] == '\0') { // Verifică dacă username-ul este gol
        fprintf(stderr, "Eroare: Numele de utilizator nu poate fi gol.\n");
        return 0; // Invalid
    }
    if (t->clue[0] == '\0') { // Verifică dacă indiciul este gol
        fprintf(stderr, "Eroare: Indiciul (clue) nu poate fi gol.\n");
        return 0; // Invalid
    }
    // Se pot adăuga și alte validări aici
    return 1; // Valid
}

/*

check_id_exists: Verifică dacă un treasure_id specificat există deja în fișierul treasures.bin al unui hunt_id.
Deschide fișierul de comori folosind open în mod read-only (O_RDONLY).
Tratează cazul special ENOENT (fișierul nu există), returnând 0 (negăsit).
Într-o buclă while, citește câte o structură Treasure folosind read. Argumentul &current_treasure pasează adresa unde read să scrie datele.
Verifică dacă s-a citit o structură completă.
Compară câmpul id al structurii citite cu treasure_id căutat. Dacă se potrivesc, setează found = 1 și iese din buclă.
După buclă, verifică dacă read a returnat o eroare (< 0).
Închide fișierul cu close.
Returnează 1 (găsit), 0 (negăsit) sau -1 (eroare la citire/deschidere).

*/


// Verifică dacă un ID de comoară există deja (folosind open/read)
int check_id_exists(const char *hunt_id, int treasure_id) {
    char treasure_file_path[MAX_PATH_LEN]; // Buffer pentru calea fișierului
    // Construiește calea către fișierul de comori
    if (get_treasure_file_path(treasure_file_path, sizeof(treasure_file_path), hunt_id) != 0) {
        return -1; // Eroare la cale
    }

    // Deschide fișierul de comori DOAR pentru citire (O_RDONLY)
    int fd = open(treasure_file_path, O_RDONLY);
    if (fd == -1) { // Verifică dacă deschiderea a eșuat
        if (errno == ENOENT) { // ENOENT = Fișierul nu există
            return 0; // Dacă fișierul nu există, ID-ul nu poate exista
        }
        // Altă eroare la deschidere
        perror("Eroare la deschiderea fișierului de comori pentru verificare ID");
        fprintf(stderr, "Cale fișier: %s\n", treasure_file_path);
        return -1; // Returnează eroare
    }

    Treasure current_treasure; // Variabilă temporară pentru a citi fiecare comoară
    ssize_t bytes_read;       // Numărul de octeți citiți de read()
    int found = 0;            // Flag pentru a indica dacă ID-ul a fost găsit

    // Citește înregistrări din fișier până la sfârșit sau eroare
    // read(descriptor, buffer_destinație, nr_octeți)
    while ((bytes_read = read(fd, &current_treasure, sizeof(Treasure))) > 0) {
        // Verifică dacă s-a citit o înregistrare completă
        if (bytes_read < sizeof(Treasure)) {
            fprintf(stderr, "Avertisment: Fișierul de comori pare trunchiat în timpul verificării ID-ului.\n");
            break; // Oprește căutarea dacă fișierul e corupt
        }
        // Compară ID-ul citit cu cel căutat
        if (current_treasure.id == treasure_id) {
            found = 1; // Am găsit ID-ul
            break;     // Ieși din buclă
        }
    }

    // Verifică dacă a apărut o eroare în timpul citirii (read a returnat -1)
    if (bytes_read < 0) {
        perror("Eroare la citirea fișierului de comori în timpul verificării ID");
        found = -1; // Marchează ca eroare
    }

    // Închide fișierul
    if (close(fd) == -1) {
         perror("Avertisment: Eroare la închiderea fișierului de comori după verificare ID");
         // Nu suprascrie statusul 'found' dacă a fost eroare la închidere
    }
    return found; // Returnează 1 (găsit), 0 (negăsit), -1 (eroare)
}



/*

prompt_for_treasure_details: Aceasta este o funcție cheie pentru interacțiunea cu utilizatorul la adăugarea unei comori. Înlocuiește vechea createTreasure.
Folosește fgets pentru a citi fiecare intrare ca șir de caractere într-un buffer, prevenind buffer overflows.
Pentru numere (ID, Lat, Lon, Value), folosește strtol (pentru întregi) și strtof (pentru flotanți) pentru a converti string-ul din buffer. Aceste funcții sunt mai robuste decât scanf sau atoi.
Verifică riguros rezultatul conversiilor: verifică errno, pointerul endptr (pentru a vedea dacă s-a convertit ceva și dacă au rămas caractere nevalide după număr) și limitele (ex: ID > 0, valoarea să încapă în int).
Pentru ID, include o buclă while care re-cere ID-ul până când este introdus unul valid numeric și unic (verificat cu check_id_exists).
Pentru string-uri (username, clue), elimină caracterul newline \n lăsat de fgets folosind strcspn.
Verifică dacă string-urile nu sunt goale.
La final, apelează validate_treasure_data pentru o ultimă verificare generală.
Returnează 0 la succes, -1 la orice eroare de input sau validare.
*/


// Cere utilizatorului detalii despre comoară (înlocuiește createTreasure)
// Folosește fgets și parsare robustă
int prompt_for_treasure_details(Treasure *t, const char *hunt_id) {
    if (!t) return -1; // Verificare pointer comoară
    char buffer[MAX_INPUT_BUFFER]; // Buffer general pentru citire input
    char *endptr; // Pointer folosit de strtol/strtof pentru a verifica conversia

    // --- Treasure ID ---
    while (1) { // Buclă până când se introduce un ID valid și unic
        printf("Introdu ID-ul comorii (număr întreg pozitiv): ");
        // Citește linia întreagă în buffer, prevenind overflow
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
             fprintf(stderr, "Eroare de input sau EOF la citirea ID-ului.\n"); return -1;
        }
        errno = 0; // Resetează errno înainte de conversie
        // Convertește string-ul din buffer în long integer (baza 10)
        long val_l = strtol(buffer, &endptr, 10);
        // Verifică erorile de conversie:
        // 1. errno != 0 (ex: overflow)
        // 2. endptr == buffer (nu s-a convertit niciun caracter)
        // 3. *endptr != '\0' && !isspace(*endptr) (există caractere non-spațiu după număr)
        // 4. val_l <= 0 (ID trebuie să fie pozitiv)
        // 5. val_l > INT_MAX (a depășit limita int)
        if (errno != 0 || endptr == buffer || (*endptr != '\0' && !isspace(*endptr)) || val_l <= 0 || val_l > INT_MAX) {
            fprintf(stderr, "Input invalid. Introduceți un număr întreg pozitiv.\n");
            continue; // Cere din nou input
        }
        t->id = (int)val_l; // Stochează ID-ul valid

        // Verifică dacă ID-ul există deja
        int id_status = check_id_exists(hunt_id, t->id);
        if (id_status == 1) { // ID găsit
            fprintf(stderr, "Eroare: ID-ul %d există deja în acest hunt. Alegeți altul.\n", t->id);
            // Rămâne în buclă pentru a cere alt ID
        } else if (id_status == -1) { // Eroare la verificare
            fprintf(stderr, "Eroare la verificarea ID-urilor existente. Adăugarea nu poate continua.\n");
            return -1; // Eroare fatală
        } else { // ID negăsit (id_status == 0)
            break; // ID-ul este valid și unic, ieși din buclă
        }
    } // Sfârșit buclă while ID

    // --- User Name ---
    printf("Introdu username-ul (max %d caractere): ", MAX_USERNAME_LEN - 1);
    // Citește username-ul în câmpul structurii
    if (fgets(t->username, MAX_USERNAME_LEN, stdin) == NULL) { /* ... eroare ... */ return -1; }
    // Elimină caracterul newline ('\n') adăugat de fgets, dacă există
    t->username[strcspn(t->username, "\n")] = 0;
    // Verifică dacă username-ul e gol
    if (t->username[0] == '\0') { /* ... eroare ... */ return -1; }

    // --- Latitude ---
    printf("Introdu latitudinea (număr real, ex: 44.43): ");
    // Citește în buffer
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) { /* ... eroare ... */ return -1; }
    errno = 0;
    // Convertește string-ul în float
    t->coordinates.latitude = strtof(buffer, &endptr);
    // Verifică erorile de conversie (similar cu strtol)
    if (errno != 0 || endptr == buffer || (*endptr != '\0' && !isspace(*endptr))) {
        fprintf(stderr, "Input invalid pentru latitudine. Introduceți un număr.\n"); return -1;
    }

    // --- Longitude --- (Similar cu Latitude)
    printf("Introdu longitudinea (număr real, ex: 26.10): ");
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) { /* ... eroare ... */ return -1; }
    errno = 0;
    t->coordinates.longitude = strtof(buffer, &endptr);
    if (errno != 0 || endptr == buffer || (*endptr != '\0' && !isspace(*endptr))) {
        fprintf(stderr, "Input invalid pentru longitudine. Introduceți un număr.\n"); return -1;
    }

    // --- Clue Text ---
    printf("Introdu indiciul (max %d caractere): ", MAX_CLUE_LEN - 1);
    // Citește indiciul
    if (fgets(t->clue, MAX_CLUE_LEN, stdin) == NULL) { /* ... eroare ... */ return -1; }
    t->clue[strcspn(t->clue, "\n")] = 0; // Elimină newline
    // Verifică dacă e gol
    if (t->clue[0] == '\0') { /* ... eroare ... */ return -1; }

    // --- Value ---
    printf("Introdu valoarea (număr întreg): ");
    // Citește în buffer
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) { /* ... eroare ... */ return -1; }
    errno = 0;
    // Convertește în long
    long val_val = strtol(buffer, &endptr, 10);
    // Verifică erorile (similar cu ID, dar permite și 0 sau negativ, și verifică limitele INT)
     if (errno != 0 || endptr == buffer || (*endptr != '\0' && !isspace(*endptr)) || val_val > INT_MAX || val_val < INT_MIN) {
        fprintf(stderr, "Input invalid pentru valoare. Introduceți un număr întreg.\n"); return -1;
    }
    t->value = (int)val_val; // Stochează valoarea

    // Apelăm funcția de validare generală a datelor colectate
    if (!validate_treasure_data(t)) {
        // Mesajul specific a fost deja afișat
        return -1;
    }

    return 0; // Toate datele au fost citite și validate cu succes
}


// Afișează detaliile unei comori (înlocuiește showTreasure)
void print_treasure(const Treasure *t) {
    if (!t) return; // Verificare pointer null
    // Afișează fiecare câmp al structurii Treasure *t
    printf("  ID:          %d\n", t->id);
    printf("  Utilizator:  %s\n", t->username);
    // Afișează coordonatele float cu 6 zecimale
    printf("  GPS (Lat,Lon): (%.6f, %.6f)\n", t->coordinates.latitude, t->coordinates.longitude);
    printf("  Indiciu:     \"%s\"\n", t->clue);
    printf("  Valoare:     %d\n", t->value);
    printf("  ----\n"); // Separator vizual
}



// --- Handlers Comenzi ---

/*
handle_add: Gestionează comanda add.
Obține căile necesare.
Încearcă să creeze directorul hunt-ului cu mkdir. Dacă directorul există deja (errno == EEXIST), continuă normal. Dacă e o altă eroare, oprește. Dacă directorul este creat acum, creează și fișierul de log gol și symlink-ul asociat și loghează crearea hunt-ului.
Apelează prompt_for_treasure_details pentru a obține datele comorii de la utilizator, inclusiv verificarea unicității ID-ului.
Deschide fișierul treasures.bin folosind open cu flag-urile O_WRONLY (scriere), O_CREAT (creare dacă nu există), O_APPEND (scrie mereu la sfârșit).
Scrie structura new_treasure în fișier folosind write. Verifică dacă scrierea a reușit și dacă s-a scris numărul corect de octeți.
Folosește goto cleanup_add pentru a ajunge la codul care închide fișierul (close(fd)), indiferent dacă scrierea a reușit sau a eșuat (cu excepția erorilor foarte timpurii).
Dacă operația a reușit (return_status == 0), apelează log_operation.
Returnează 0 la succes, -1 la eșec.
*/

// Adaugă o comoară (folosind open/write)
int handle_add(const char *hunt_id) {
    char hunt_path[MAX_PATH_LEN];         // Calea directorului hunt
    char treasure_file_path[MAX_PATH_LEN]; // Calea fișierului de comori
    char log_file_path[MAX_PATH_LEN];      // Calea fișierului de log
    char log_msg[MAX_INPUT_BUFFER];        // Buffer pentru mesajul de log
    int return_status = -1;                // Statusul returnat (presupune eșec inițial)
    int fd = -1;                           // Descriptor fișier comori (-1 = neinițializat/închis)
    int logfd = -1;                        // Descriptor pentru crearea inițială a log-ului

    // Obține căile necesare
    if (get_hunt_path(hunt_path, sizeof(hunt_path), hunt_id) != 0) return -1;
    if (get_treasure_file_path(treasure_file_path, sizeof(treasure_file_path), hunt_id) != 0) return -1;
    if (get_log_file_path(log_file_path, sizeof(log_file_path), hunt_id) != 0) return -1;

    // Creăm directorul hunt folosind mkdir(cale, permisiuni)
    if (mkdir(hunt_path, DIR_PERMS) == -1) { // Încearcă să creeze directorul
        // Verifică dacă eroarea este EEXIST (directorul există deja)
        if (errno != EEXIST) {
            perror("Eroare la crearea directorului hunt"); // Altă eroare
            fprintf(stderr, "Director: %s\n", hunt_path);
            return -1; // Eșec
        }
        // Directorul exista deja, nu facem nimic special aici
    } else { // mkdir a reușit (directorul a fost creat ACUM)
        printf("Director hunt creat: %s\n", hunt_path);
        // Fiind nou, creăm fișierul de log gol și symlink-ul
        // Deschide (sau creează) fișierul de log cu O_TRUNC pentru a fi gol
        logfd = open(log_file_path, O_WRONLY | O_CREAT | O_TRUNC, FILE_PERMS);
        if (logfd == -1) {
            perror("Avertisment: Nu s-a putut crea fișierul de log inițial");
        } else {
            close(logfd); // Închidem imediat, l-am creat doar
            // Încercăm să creăm symlink-ul
            if (create_log_symlink(hunt_id) != 0) {
                // Afișăm avertisment dacă symlink-ul eșuează
            }
        }
        // Logăm evenimentul de creare a hunt-ului
        snprintf(log_msg, sizeof(log_msg), "CREARE Hunt '%s'", hunt_id);
        log_operation(hunt_id, log_msg); // Apelăm funcția de logare
    }

    Treasure new_treasure; // Declarăm o variabilă pentru noua comoară
    printf("Adăugare comoară nouă în hunt '%s'.\n", hunt_id);
    // Obținem detaliile comorii de la utilizator (cu validări)
    if (prompt_for_treasure_details(&new_treasure, hunt_id) != 0) {
        fprintf(stderr, "Eșec la obținerea detaliilor comorii. Adăugare anulată.\n");
        return -1; // Eșec
    }

    // Deschidem fișierul de comori folosind open()
    // O_WRONLY: Doar scriere
    // O_CREAT: Creează fișierul dacă nu există
    // O_APPEND: Scrie mereu la sfârșitul fișierului (nu suprascrie)
    // FILE_PERMS: Permisiunile dacă fișierul este creat
    fd = open(treasure_file_path, O_WRONLY | O_CREAT | O_APPEND, FILE_PERMS);
    if (fd == -1) { // Verifică eroarea la deschidere
        perror("Eroare la deschiderea fișierului de comori pentru scriere");
        fprintf(stderr, "Fișier: %s\n", treasure_file_path);
        goto cleanup_add; // Sari la secțiunea de cleanup
    }

    // Scriem structura new_treasure în fișier folosind write()
    // write(descriptor, pointer_la_date, nr_octeți)
    ssize_t bytes_written = write(fd, &new_treasure, sizeof(Treasure));
    if (bytes_written < 0) { // write a returnat eroare
        perror("Eroare la scrierea înregistrării comorii");
        goto cleanup_add; // Cleanup
    }
    // Verifică dacă s-au scris toți octeții așteptați
    if (bytes_written < sizeof(Treasure)) {
        fprintf(stderr, "Eroare: Scriere incompletă în fișierul de comori (%zd/%zu octeți).\n", bytes_written, sizeof(Treasure));
        goto cleanup_add; // Cleanup
    }

    // Dacă am ajuns aici, scrierea a reușit
    printf("Comoara cu ID %d adăugată cu succes în hunt '%s'.\n", new_treasure.id, hunt_id);
    return_status = 0; // Marcăm succes

// Etichetă pentru cleanup (închidere fișier)
cleanup_add:
    if (fd != -1) { // Dacă fișierul a fost deschis (fd valid)
        if (close(fd) == -1) { // Încearcă să închidă
            perror("Avertisment: Eroare la închiderea fișierului de comori după add");
             // Păstrăm statusul de succes dacă operația principală a reușit
             if (return_status == 0) return_status = 0; else return_status = -1;
        }
    }

    // Logăm operația de ADD doar dacă a avut succes (return_status == 0)
    if (return_status == 0) {
        // Formatăm mesajul de log
        snprintf(log_msg, sizeof(log_msg), "ADD Comoară ID: %d, Utilizator: %s", new_treasure.id, new_treasure.username);
        // Apelăm funcția de logare
        if (log_operation(hunt_id, log_msg) != 0) {
            // Afișăm avertisment dacă logarea eșuează
        }
    }

    return return_status; // Returnează 0 (succes) sau -1 (eșec)
}

/*

handle_list: Gestionează comanda list.
Verifică existența directorului hunt.
Obține calea fișierului de comori.
Folosește stat pentru a obține informații despre fișierul de comori (treasures.bin).
Dacă stat eșuează cu ENOENT, afișează că hunt-ul e gol și returnează succes. Dacă e altă eroare stat, returnează eroare.
Dacă stat reușește, afișează numele fișierului, dimensiunea (file_stat.st_size) și data ultimei modificări (ctime(&file_stat.st_mtime)), conform cerinței.
Dacă dimensiunea e mai mare ca 0, deschide fișierul cu open (O_RDONLY).
Într-o buclă while, citește structuri Treasure folosind read.
Pentru fiecare structură citită corect, o afișează folosind print_treasure și incrementează treasure_count.
Gestionează citirile parțiale și erorile de citire.
Închide fișierul cu close.
Loghează operația, indicând numărul de comori listate și dacă au fost erori.
Returnează 0 la succes (chiar dacă lista e goală), -1 la eroare de acces/citire.
*/

// Listează comorile (folosind stat și open/read)
int handle_list(const char *hunt_id) {
    char treasure_file_path[MAX_PATH_LEN]; // Cale fișier comori
    char hunt_path[MAX_PATH_LEN];         // Cale director hunt
    char log_msg[MAX_INPUT_BUFFER];        // Buffer mesaj log
    struct stat file_stat;                 // Structură pentru informații fișier (din stat)
    int fd = -1;                           // Descriptor fișier comori
    int return_status = -1;                // Status returnat
    int treasure_count = 0;                // Contor comori listate

    // Verificăm existența și tipul directorului hunt
    if (get_hunt_path(hunt_path, sizeof(hunt_path), hunt_id) != 0) return -1;
    if (stat(hunt_path, &file_stat) == -1) { /* ... eroare director inexistent ... */ return -1; }
    if (!S_ISDIR(file_stat.st_mode)) { /* ... eroare nu e director ... */ return -1; }

    // Obținem calea fișierului de comori
    if (get_treasure_file_path(treasure_file_path, sizeof(treasure_file_path), hunt_id) != 0) return -1;

    printf("--- Hunt: %s ---\n", hunt_id); // Antet listare

    // Obținem informații despre fișierul de comori folosind stat()
    if (stat(treasure_file_path, &file_stat) == -1) { // stat a eșuat
        if (errno == ENOENT) { // Fișierul nu există
            printf("Fișier comori: %s (Nu există sau gol)\n", TREASURE_FILE_NAME);
            printf("Dimensiune: 0 octeți\n");
            printf("Ultima modificare: N/A\n");
            printf("--------------------\n");
            printf("  (Nicio comoară găsită)\n");
            // Nu e o eroare fatală, doar un hunt gol. Setăm succes.
            return_status = 0;
        } else { // Altă eroare stat()
            perror("Eroare la obținerea statisticilor fișierului de comori");
            printf("Fișier comori: %s (Eroare acces)\n", TREASURE_FILE_NAME);
            printf("--------------------\n");
            return -1; // Eroare
        }
    } else { // stat a reușit, fișierul există
        // Afișăm informațiile cerute de specificație
        printf("Fișier comori: %s\n", TREASURE_FILE_NAME);
        printf("Dimensiune: %lld octeți\n", (long long)file_stat.st_size); // st_size = dimensiunea
        // ctime formatează data ultimei modificări (st_mtime)
        printf("Ultima modificare: %s", ctime(&file_stat.st_mtime));
        printf("--------------------\n");
        printf("Comori:\n");

        // Deschidem și citim doar dacă fișierul are conținut
        if (file_stat.st_size > 0) {
            // Deschidem DOAR pentru citire (O_RDONLY)
            fd = open(treasure_file_path, O_RDONLY);
            if (fd == -1) { // Eroare la deschidere (ex: permisiuni)
                perror("Eroare la deschiderea fișierului de comori pentru citire");
                printf("  (Eroare la citirea fișierului)\n");
                return_status = -1; // Marcăm eroare
            } else { // Deschiderea a reușit
                Treasure current_treasure; // Buffer pentru citire
                ssize_t bytes_read;       // Rezultat read()
                // Citim înregistrări până la sfârșit sau eroare
                while ((bytes_read = read(fd, &current_treasure, sizeof(Treasure))) > 0) {
                    // Verificăm citirea completă
                    if (bytes_read < sizeof(Treasure)) {
                         fprintf(stderr, "\nAvertisment: Fișierul de comori pare trunchiat...\n");
                         return_status = -1; // Considerăm eroare
                         break; // Oprim citirea
                    }
                    treasure_count++; // Incrementăm contorul
                    print_treasure(&current_treasure); // Afișăm comoara
                }
                // Verificăm dacă bucla s-a terminat cu eroare de citire
                if (bytes_read < 0) {
                    perror("Eroare la citirea din fișierul de comori");
                    return_status = -1; // Marcăm eroare
                }
                 // Închidem fișierul
                 if (close(fd) == -1) {
                     perror("Avertisment: Eroare la închiderea fișierului de comori după list");
                      if (return_status == 0) return_status = 0; // Păstrăm succesul dacă era cazul
                 }
                 fd = -1; // Marcat ca închis
            } // Sfârșit else (deschidere reușită)
        } // Sfârșit if (file_stat.st_size > 0)

        // Afișăm mesaj dacă fișierul exista dar nu am putut citi comori
        if (treasure_count == 0) {
             if (return_status != -1) printf("  (Nicio comoară în fișier sau fișier corupt)\n");
             else printf("  (Eroare la citirea comorilor)\n"); // Dacă a fost eroare de open/read
        }
    } // Sfârșit else (stat reușit)

    printf("--------------------\n"); // Sfârșit listare

    // Setăm statusul final de succes dacă nu a fost marcat ca eroare
    if (return_status != -1) {
         return_status = 0;
    }

    // Logăm operația
    snprintf(log_msg, sizeof(log_msg), "LIST Hunt (%d comori listate%s)", treasure_count, (return_status == -1 ? ", erori întâmpinate" : ""));
    log_operation(hunt_id, log_msg); // Ignorăm eșecul logării

    return return_status; // Returnăm 0 (succes) sau -1 (eșec)
}


/*
handle_view: Gestionează comanda view.
Primește treasure_id ca int (convertit în main).
Deschide fișierul treasures.bin cu open (O_RDONLY).
Citește structuri Treasure cu read într-o buclă while.
Compară current_treasure.id cu treasure_id căutat.
Dacă găsește ID-ul, afișează detaliile comorii folosind print_treasure, setează found = 1 și iese din buclă.
Gestionează citirile parțiale și erorile de citire.
După buclă, determină statusul: 0 dacă a fost găsită sau dacă nu a fost găsită dar nu au fost erori, -1 dacă a apărut o eroare de citire.
Închide fișierul (goto cleanup_view și close).
Loghează operația, indicând dacă a fost găsită, negăsită sau a eșuat.
Returnează 0 (operație completă) sau -1 (eroare I/O).
*/


// Vizualizează o comoară specifică (folosind open/read)
int handle_view(const char *hunt_id, int treasure_id) {
    char treasure_file_path[MAX_PATH_LEN]; // Cale fișier comori
    char log_msg[MAX_INPUT_BUFFER];        // Buffer mesaj log
    int fd = -1;                           // Descriptor fișier
    int found = 0;                         // Flag găsit
    int return_status = -1;                // Status returnat

    // Obține calea fișierului
    if (get_treasure_file_path(treasure_file_path, sizeof(treasure_file_path), hunt_id) != 0) return -1;

    // Deschide pentru citire
    fd = open(treasure_file_path, O_RDONLY);
    if (fd == -1) { // Verifică eroare deschidere
        if (errno == ENOENT) fprintf(stderr,"Eroare: Hunt '%s' sau fișierul său de comori nu există.\n", hunt_id);
        else perror("Eroare la deschiderea fișierului de comori pentru vizualizare");
        goto cleanup_view; // Sari la cleanup
    }

    Treasure current_treasure; // Buffer citire
    ssize_t bytes_read;       // Rezultat read
    int read_error = 0;       // Flag eroare citire

    // Citește înregistrări
    while ((bytes_read = read(fd, &current_treasure, sizeof(Treasure))) > 0) {
        // Verifică citire completă
        if (bytes_read < sizeof(Treasure)) {
            fprintf(stderr, "Avertisment: Fișierul de comori pare trunchiat în timpul căutării.\n");
            read_error = 1; // Marchează eroare citire
            break; // Oprește
        }
        // Compară ID-ul citit cu cel căutat
        if (current_treasure.id == treasure_id) {
            printf("--- Detalii Comoară (Hunt: %s, ID: %d) ---\n", hunt_id, treasure_id);
            print_treasure(&current_treasure); // Afișează comoara găsită
            printf("-------------------------------------------\n");
            found = 1; // Marchează ca găsită
            break;     // Ieși din buclă
        }
    }

    // Verifică eroare la ultimul read
     if (bytes_read < 0) {
        perror("Eroare la citirea din fișierul de comori în timpul vizualizării");
        read_error = 1; // Marchează eroare citire
    }

    // Stabilește statusul final
    if (found) {
        return_status = 0; // Succes, găsită
    } else if (!read_error) { // Negăsită, dar fără erori de citire
        printf("Comoara cu ID %d nu a fost găsită în hunt '%s'.\n", treasure_id, hunt_id);
        return_status = 0; // Operația view s-a terminat corect
    } else { // Negăsită ȘI eroare de citire
        fprintf(stderr, "Vizualizarea a eșuat din cauza unei erori de citire.\n");
        return_status = -1; // Eșec
    }

// Etichetă cleanup
cleanup_view:
    if (fd != -1) { // Dacă fișierul a fost deschis
        if (close(fd) == -1) { // Închide
            perror("Avertisment: Eroare la închiderea fișierului de comori după view");
        }
    }
    // Logăm operația în funcție de rezultat
    if (found) snprintf(log_msg, sizeof(log_msg), "VIEW Comoară ID: %d (Găsită)", treasure_id);
    else if (return_status == 0) snprintf(log_msg, sizeof(log_msg), "VIEW Comoară ID: %d (Negăsită)", treasure_id);
    else snprintf(log_msg, sizeof(log_msg), "VIEW Comoară ID: %d (Eșuat din cauza erorii)", treasure_id);
    log_operation(hunt_id, log_msg);

    return return_status; // Returnează 0 (terminat corect) sau -1 (eroare I/O)
}

/*

handle_remove_treasure: Gestionează ștergerea unei comori. Aceasta este cea mai complexă operație de fișier.
Obține calea către fișierul original și construiește o cale pentru un fișier temporar (ex: treasures.bin.tmp) în același director cu cel original.
Verifică dacă fișierul original există cu stat și îi preia permisiunile (original_mode).
Deschide fișierul original pentru citire (fd_read) cu open.
Deschide fișierul temporar pentru scriere (fd_write) cu open, folosind flag-urile O_WRONLY | O_CREAT | O_TRUNC (TRUNC este esențial pentru a goli fișierul dacă exista) și permisiunile originale.
Într-o buclă while, citește (read) o înregistrare din fd_read.
Dacă ID-ul citit nu este cel de șters, scrie (write) înregistrarea în fd_write.
Dacă ID-ul este cel de șters, marchează found = 1 și nu scrie înregistrarea în fd_write.
Gestionează erorile de citire/scriere și citirile/scrierile parțiale, setând error_occurred = 1.
După buclă, închide ambele fișiere (close).
Verifică flag-urile error_occurred și found:
Dacă error_occurred, afișează eroare, încearcă să șteargă fișierul temporar cu unlink și returnează -1.
Dacă !found (și nu au fost erori), afișează "negăsit", șterge fișierul temporar cu unlink, loghează "Negăsită" și returnează 0.
Dacă found (și nu au fost erori), încearcă să înlocuiască fișierul original cu cel temporar folosind rename(temp_file_path, treasure_file_path). rename este preferat față de unlink+link sau copiere pentru că este adesea o operație atomică. Dacă rename reușește,
 loghează "Succes" și returnează 0. Dacă rename eșuează, afișează o eroare critică și returnează -1.


*/

// Șterge o comoară (folosind open/read/write/rename/unlink)
int handle_remove_treasure(const char *hunt_id, int treasure_id) {
    char treasure_file_path[MAX_PATH_LEN]; // Cale fișier original
    char temp_file_path[MAX_PATH_LEN + 5]; // Cale fișier temporar (.tmp)
    char hunt_path[MAX_PATH_LEN];         // Cale director hunt (pt temp)
    char log_msg[MAX_INPUT_BUFFER];        // Buffer log
    int fd_read = -1, fd_write = -1;       // Descriptori pt citire/scriere
    int found = 0;                         // Flag găsit
    int error_occurred = 0;                // Flag eroare generală
    int return_status = -1;                // Status returnat
    mode_t original_mode = FILE_PERMS;     // Permisiuni originale (default)

    // Obține căi
    if (get_hunt_path(hunt_path, sizeof(hunt_path), hunt_id) != 0) return -1;
    if (get_treasure_file_path(treasure_file_path, sizeof(treasure_file_path), hunt_id) != 0) return -1;
    // Construiește calea temp ÎN directorul hunt (ex: ./hunt1/treasures.bin.tmp)
    snprintf(temp_file_path, sizeof(temp_file_path), "%s/%s.tmp", hunt_path, TREASURE_FILE_NAME);

    // Verifică existența fișierului original și preia permisiunile
    struct stat file_stat;
    if (stat(treasure_file_path, &file_stat) == -1) { /* ... eroare, nu există ... */ return -1; }
    original_mode = file_stat.st_mode & 0777; // Extrage partea de permisiuni

    // Deschide fișierul original pentru citire
    fd_read = open(treasure_file_path, O_RDONLY);
    if (fd_read == -1) { /* ... eroare deschidere ... */ return -1; }

    // Deschide fișierul temporar pentru scriere
    // O_WRONLY: Scriere
    // O_CREAT: Creează dacă nu există
    // O_TRUNC: Golește fișierul dacă există (CRUCIAL!)
    // original_mode: Aplică permisiunile originale la creare
    fd_write = open(temp_file_path, O_WRONLY | O_CREAT | O_TRUNC, original_mode);
    if (fd_write == -1) {
        perror("Eroare la crearea fișierului temporar pentru ștergere");
        fprintf(stderr,"Cale temp: %s\n", temp_file_path);
        close(fd_read); // Închide fișierul original înainte de a ieși
        return -1;
    }

    // Bucla principală: citește din original, scrie în temporar (dacă ID-ul nu corespunde)
    Treasure current_treasure;
    ssize_t bytes_read, bytes_written;
    while ((bytes_read = read(fd_read, &current_treasure, sizeof(Treasure))) > 0) {
        // Verifică citire completă
        if (bytes_read < sizeof(Treasure)) {
            /* ... eroare fișier corupt ... */ error_occurred = 1; break;
        }
        // Verifică dacă ID-ul este cel de șters
        if (current_treasure.id == treasure_id) {
            found = 1; // Marchează că l-am găsit (NU îl scriem în temp)
        } else { // ID diferit, trebuie păstrat
            // Scrie înregistrarea în fișierul temporar
            bytes_written = write(fd_write, &current_treasure, sizeof(Treasure));
            if (bytes_written < 0) { // Eroare scriere
                perror("Eroare la scrierea în fișierul temporar");
                error_occurred = 1; break;
            }
            if (bytes_written < sizeof(Treasure)) { // Scriere incompletă
                fprintf(stderr, "Eroare: Scriere incompletă în fișierul temporar...\n");
                error_occurred = 1; break;
            }
        }
    } // Sfârșit while read

    // Verifică eroare la ultimul read
    if (bytes_read < 0) { perror("Eroare la citirea din fișierul original..."); error_occurred = 1; }

    // Închidem AMBELE fișiere, indiferent de erori, și verificăm erorile la închidere
    if (close(fd_read) == -1) { perror("Avertisment: Eroare la închiderea fișierului original"); error_occurred = 1; }
    if (close(fd_write) == -1) { perror("Avertisment: Eroare la închiderea fișierului temporar"); error_occurred = 1; }
    fd_read = fd_write = -1; // Marcam ca închise

    // --- Decidem rezultatul și acțiunile finale ---
    if (error_occurred) { // Dacă a apărut vreo eroare I/O
        fprintf(stderr, "Erori apărute... Fișierul original nealterat. Curățare temp...\n");
        // Încercăm să ștergem fișierul temporar
        if (unlink(temp_file_path) == -1 && errno != ENOENT) { // unlink eșuat și nu pt că nu există
            perror("Eroare la ștergerea fișierului temporar după eroare");
        }
        return_status = -1; // Eșec
    } else if (!found) { // Dacă nu au fost erori, dar nici nu am găsit ID-ul
        printf("Comoara cu ID %d nu a fost găsită... Nicio modificare.\n", treasure_id);
        // Ștergem fișierul temporar (care ar trebui să fie identic cu originalul)
        if (unlink(temp_file_path) == -1 && errno != ENOENT) {
            perror("Avertisment: Eroare la ștergerea fișierului temporar când comoara nu a fost găsită");
        }
        // Logăm că nu a fost găsit
        snprintf(log_msg, sizeof(log_msg), "REMOVE Comoară ID: %d (Negăsită)", treasure_id);
        log_operation(hunt_id, log_msg);
        return_status = 0; // Operație completă, fără efect
    } else { // Găsită ȘI fără erori I/O
        // Înlocuim fișierul original cu cel temporar folosind rename()
        // rename este atomic pe majoritatea sistemelor de fișiere POSIX
        if (rename(temp_file_path, treasure_file_path) == -1) {
            perror("EROARE CRITICĂ: Eșec la redenumirea fișierului temporar în cel original");
            fprintf(stderr, "Fișierul original poate fi pierdut... Temp este '%s'\n", temp_file_path);
            return_status = -1; // Eșec critic
        } else { // Rename a reușit
            printf("Comoara cu ID %d a fost ștearsă cu succes...\n", treasure_id);
            // Logăm succesul
            snprintf(log_msg, sizeof(log_msg), "REMOVE Comoară ID: %d (Succes)", treasure_id);
            log_operation(hunt_id, log_msg);
            return_status = 0; // Succes
        }
    }
    return return_status; // Returnăm statusul final
}

/*
handle_remove_hunt: Gestionează ștergerea unui întreg hunt.
Obține căile necesare (director hunt, fișier comori, fișier log, symlink).
Verifică dacă directorul hunt există și este un director folosind stat. Tratează cazul ENOENT ca succes (nu e nimic de șters) și încearcă să șteargă un posibil symlink orfan.
Loghează intenția de ștergere înainte de a șterge efectiv fișierele.
Folosește unlink pentru a șterge symlink-ul, fișierul de comori și fișierul de log. Verifică erorile, dar ignoră ENOENT (fișierul nu exista, ceea ce e OK). Incrementează un contor errors la alte erori unlink.
Folosește rmdir pentru a șterge directorul hunt-ului. rmdir funcționează doar dacă directorul este gol. Verifică erorile: ignoră ENOENT, tratează specific ENOTEMPTY (directorul nu era gol, indicând o problemă sau fișiere necunoscute), și tratează alte erori rmdir.
Returnează 0 dacă errors == 0 (succes complet), altfel returnează -1 (eșec parțial sau total).
*/

// Șterge un hunt întreg (folosind unlink și rmdir)
int handle_remove_hunt(const char *hunt_id) {
    char hunt_path[MAX_PATH_LEN];         // Cale director
    char treasure_file_path[MAX_PATH_LEN]; // Cale fișier comori
    char log_file_path[MAX_PATH_LEN];      // Cale fișier log
    char symlink_path[MAX_PATH_LEN];        // Cale symlink
    char log_msg[MAX_INPUT_BUFFER];        // Buffer log
    int errors = 0;                        // Contor erori (pentru a raporta eșec parțial)

    // Obține toate căile relevante
    if (get_hunt_path(hunt_path, sizeof(hunt_path), hunt_id) != 0) return -1;
    if (get_treasure_file_path(treasure_file_path, sizeof(treasure_file_path), hunt_id) != 0) return -1;
    if (get_log_file_path(log_file_path, sizeof(log_file_path), hunt_id) != 0) return -1;
    // Construiește calea symlink-ului din directorul curent
    snprintf(symlink_path, sizeof(symlink_path), "./%s%s", LOG_SYMLINK_PREFIX, hunt_id);

    // Verifică dacă directorul hunt există și este director
    struct stat st;
    if (stat(hunt_path, &st) == -1) { // Verifică existența
        if (errno == ENOENT) { // Nu există
            printf("Hunt '%s' nu există. Nimic de șters.\n", hunt_id);
             // Încercăm să ștergem symlink-ul orfan, dacă există
             if (unlink(symlink_path) == -1 && errno != ENOENT) {
                 perror("Avertisment: Eșec la ștergerea symlink-ului orfan");
                 // Nu incrementăm `errors` aici, e doar un avertisment
             }
            return 0; // Succes, nu era nimic de făcut
        } else { /* ... altă eroare stat ... */ return -1; }
    }
    if (!S_ISDIR(st.st_mode)) { // Există, dar nu e director
        fprintf(stderr, "Eroare: '%s' există dar nu este un director...\n", hunt_path);
         // Încercăm să ștergem symlink-ul care poate indica spre el
         if (unlink(symlink_path) == -1 && errno != ENOENT) {
             perror("Avertisment: Eșec la ștergerea symlink-ului către un non-director");
         }
        return -1; // Eroare
    }

    // Directorul există și e director
    printf("Se încearcă ștergerea hunt-ului '%s' și a conținutului său cunoscut...\n", hunt_id);

    // Logăm intenția de ștergere *înainte* de a șterge efectiv fișierul de log
    snprintf(log_msg, sizeof(log_msg), "REMOVE Hunt (încercare ștergere completă)");
    log_operation(hunt_id, log_msg); // Ignorăm erorile de logare aici

    // 1. Ștergem symlink-ul. `unlink()` șterge fișiere sau symlink-uri.
    // Ignorăm eroarea dacă fișierul nu există (errno == ENOENT)
    if (unlink(symlink_path) == -1 && errno != ENOENT) {
        perror("Avertisment: Eșec la ștergerea symlink-ului de log"); errors++;
    }

    // 2. Ștergem fișierul de comori
    if (unlink(treasure_file_path) == -1 && errno != ENOENT) {
        perror("Avertisment: Eșec la ștergerea fișierului de comori"); errors++;
    }

    // 3. Ștergem fișierul de log
    if (unlink(log_file_path) == -1 && errno != ENOENT) {
        perror("Avertisment: Eșec la ștergerea fișierului de log"); errors++;
    }

    // 4. Ștergem directorul hunt. `rmdir()` șterge doar directoare goale.
    if (rmdir(hunt_path) == -1) {
        if (errno == ENOENT) { /* Directorul a dispărut între timp? OK. */ }
        else if (errno == ENOTEMPTY) { // Directorul nu era gol!
            perror("Eroare la ștergerea directorului hunt - nu era gol");
            fprintf(stderr, "Director: %s\n", hunt_path);
            fprintf(stderr, "Ștergeți manual fișierele rămase neașteptate.\n"); errors++;
        } else { // Altă eroare rmdir
            perror("Eroare la ștergerea directorului hunt"); errors++;
        }
    }

    // Raportăm rezultatul final
    if (errors == 0) {
        printf("Hunt '%s' șters cu succes.\n", hunt_id);
        return 0; // Succes complet
    } else {
        fprintf(stderr, "Încercarea de ștergere pentru hunt '%s' s-a terminat cu %d avertisment(e)/eroare(i).\n", hunt_id, errors);
        return -1; // Eșec parțial sau total
    }
}

/*
main: Punctul de intrare al programului.
Verifică dacă există suficiente argumente pe linia de comandă (argc).
Preia comanda (argv[1]) și hunt_id (argv[2]).
Efectuează o validare de bază a hunt_id (să nu fie gol, . , .. sau să conțină /).
Dacă comanda este view sau remove_treasure, verifică dacă există al treilea argument (argv[3]) și încearcă să-l convertească într-un int (treasure_id_int) folosind strtol cu verificare robustă a erorilor.
Folosește strcmp pentru a compara command cu comenzile valide.
Pentru fiecare comandă validă, verifică numărul exact de argumente așteptat și apelează funcția handler corespunzătoare, pasându-i argumentele necesare (inclusiv treasure_id_int unde e cazul).
Stochează valoarea returnată de handler ( 0 sau -1) în result.
Dacă comanda nu este recunoscută, afișează eroare și instrucțiunile de utilizare.
La final, returnează EXIT_SUCCESS (convențional 0) dacă result este 0, sau EXIT_FAILURE (convențional 1) dacă result este -1, semnalând sistemului de operare dacă programul s-a terminat cu succes sau cu eroare.
*/

// --- Funcția Principală ---
int main(int argc, char *argv[]) {
    // Verifică numărul minim de argumente (program + comandă + hunt_id)
    if (argc < 3) {
        print_usage(argv[0]); // Afișează utilizarea
        return EXIT_FAILURE; // Cod de ieșire pentru eșec
    }

    const char *command = argv[1]; // Primul argument e comanda
    const char *hunt_id = argv[2]; // Al doilea argument e hunt_id
    int treasure_id_int = -1;     // Inițializează ID-ul comorii (pt view/remove)

    // Validare de bază pentru hunt_id
    if (hunt_id[0] == '\0' || strcmp(hunt_id, ".") == 0 || strcmp(hunt_id, "..") == 0 || strchr(hunt_id, '/')) {
        fprintf(stderr, "Eroare: hunt_id invalid '%s'. Nu poate fi gol, '.', '..', sau conține '/'.\n", hunt_id);
        return EXIT_FAILURE;
    }

    // Procesează al treilea argument (treasure_id) DOAR dacă comanda este 'view' sau 'remove_treasure'
    if ((strcmp(command, "view") == 0 || strcmp(command, "remove_treasure") == 0)) {
        // Verifică dacă există al treilea argument (argv[3])
        if (argc < 4) {
            print_usage(argv[0]); // Număr insuficient de argumente
            return EXIT_FAILURE;
        }
        // Convertește argv[3] (string) în int folosind strtol pentru robustețe
        char *endptr;
        errno = 0; // Resetează errno
        long val_l = strtol(argv[3], &endptr, 10); // Conversie baza 10
        // Verifică erorile de conversie (similar cu prompt_for_treasure_details)
        if (errno != 0 || endptr == argv[3] || (*endptr != '\0' && !isspace(*endptr)) || val_l <= 0 || val_l > INT_MAX) {
             fprintf(stderr, "Eroare: treasure_id invalid '%s'. Trebuie să fie un număr întreg pozitiv.\n", argv[3]);
             return EXIT_FAILURE;
        }
        treasure_id_int = (int)val_l; // Stochează ID-ul convertit
    }

    int result = -1; // Variabilă pentru a stoca rezultatul handler-ului (0 sau -1)

    // Compară comanda și apelează handler-ul corespunzător
    if (strcmp(command, "add") == 0) {
        if (argc != 3) { print_usage(argv[0]); return EXIT_FAILURE; } // Verifică nr exact argumente
        result = handle_add(hunt_id); // Apelează handler
    } else if (strcmp(command, "list") == 0) {
        if (argc != 3) { print_usage(argv[0]); return EXIT_FAILURE; }
        result = handle_list(hunt_id);
    } else if (strcmp(command, "view") == 0) {
        // argc și treasure_id_int au fost deja verificate/setate
        if (argc != 4) { print_usage(argv[0]); return EXIT_FAILURE; } // Verificare suplimentară
        result = handle_view(hunt_id, treasure_id_int); // Pasează ID-ul numeric
    } else if (strcmp(command, "remove_treasure") == 0) {
        // argc și treasure_id_int au fost deja verificate/setate
        if (argc != 4) { print_usage(argv[0]); return EXIT_FAILURE; }
        result = handle_remove_treasure(hunt_id, treasure_id_int); // Pasează ID-ul numeric
    } else if (strcmp(command, "remove_hunt") == 0) {
        if (argc != 3) { print_usage(argv[0]); return EXIT_FAILURE; }
        result = handle_remove_hunt(hunt_id);
    } else { // Comanda nu este recunoscută
        fprintf(stderr, "Comandă necunoscută: %s\n\n", command);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Returnează un cod de ieșire standard bazat pe rezultatul handler-ului
    // EXIT_SUCCESS (de obicei 0) dacă result == 0
    // EXIT_FAILURE (de obicei 1) dacă result == -1
    return (result == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
