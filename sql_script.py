import sqlite3
sqlite3.connect('database.db')
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE Children (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    contact TEXT,
    sex TEXT NOT NULL,
    Date_naissance DATE NOT NULL,
    age INTEGER NOT NULL,
    Quartier TEXT NOT NULL,
    Adresse TEXT NOT NULL,
    situation_familliale TEXT,
    Fonction_pere TEXT,
    Fonction_mere TEXT,
    Fraterie TEXT,
    Problemes_sante TEXT,
    Niveau_scolaire TEXT,
    date_arret_etudes DATE,
    Experience_professionnelle TEXT,
    Demande TEXT,
    Insertion_scolaire BOOLEAN,
    Insertion_salariale BOOLEAN,
    Auto_emploi BOOLEAN,
    parent_id INTEGER NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES User(id)
)
''')

conn.commit()
cursor.close()
conn.close()