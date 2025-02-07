# Gestionnaire de Mots de Passe - Documentation

![Logo](https://example.com/logo.png) <!-- À remplacer par votre logo -->

## Table des matières

1. [Introduction](#introduction)
2. [Fonctionnalités principales](#fonctionnalités-principales)
3. [Guide d'utilisation](#guide-dutilisation)
4. [Raccourcis clavier](#raccourcis-clavier)
5. [Sécurité](#sécurité)
6. [FAQ](#faq)

## Introduction

Le Gestionnaire de Mots de Passe est une application web sécurisée qui vous permet de stocker et gérer vos mots de passe de manière chiffrée. Toutes les données sont chiffrées localement avec AES-GCM 256 bits et ne quittent jamais votre navigateur.

### Points clés

- 🔒 Chiffrement local AES-GCM 256 bits
- 💾 Aucune donnée stockée sur des serveurs
- 🚀 Interface intuitive et réactive
- 📱 Compatible mobile et bureau

## Fonctionnalités principales

### Gestion des mots de passe

- **Stockage sécurisé** : Tous les mots de passe sont chiffrés localement
- **Organisation par catégories** : Classez vos mots de passe pour un accès rapide
- **Recherche avancée** : Retrouvez rapidement vos identifiants
- **Favoris** : Marquez vos entrées importantes
- **Générateur de mots de passe** : Créez des mots de passe forts et aléatoires

### Interface utilisateur

- **Vue liste/grille** : Choisissez votre mode d'affichage préféré
- **Tri personnalisable** : Organisez vos entrées selon vos besoins
- **Glisser-déposer** : Réorganisez facilement vos mots de passe
- **Statistiques** : Visualisez la santé de vos mots de passe

## Guide d'utilisation

### Première utilisation

1. **Créer une nouvelle session**
   - Cliquez sur "Créer une nouvelle session"
   - Choisissez un mot de passe maître fort
   - Ce mot de passe sera nécessaire pour déchiffrer vos données

2. **Importer un fichier existant**
   - Cliquez sur "Importer un fichier chiffré"
   - Sélectionnez votre fichier de sauvegarde
   - Entrez votre mot de passe maître

### Gestion des mots de passe

#### Ajouter une entrée

1. Cliquez sur le bouton "+" ou utilisez `Alt + N`
2. Remplissez les champs :
   - Service (ex: Gmail, Facebook)
   - Identifiant/Email
   - Mot de passe
   - Catégorie (optionnel)
3. Utilisez le générateur de mot de passe si besoin

#### Modifier/Supprimer une entrée

- **Modifier** : Cliquez sur l'icône crayon ✏️
- **Supprimer** : Cliquez sur l'icône corbeille 🗑️
- **Copier** : Cliquez sur l'icône copier 📋
- **Révéler** : Cliquez sur l'icône œil 👁️

### Gestion des catégories

- **Créer** : Utilisez le champ en bas du panneau catégories
- **Organiser** : Glissez-déposez les entrées entre catégories
- **Filtrer** : Cliquez sur une catégorie pour filtrer les entrées

## Raccourcis clavier

| Action | Raccourci |
|--------|-----------|
| Nouvelle entrée | `Alt + N` |
| Exporter | `Alt + E` |
| Rechercher | `Ctrl + F` |
| Fermer modal | `Echap` |

## Sécurité

### Chiffrement

- Algorithme : AES-GCM 256 bits
- Dérivation de clé : PBKDF2 (100 000 itérations)
- Salt unique pour chaque fichier

### Bonnes pratiques

1. **Mot de passe maître**
   - Minimum 12 caractères
   - Mélange de majuscules, minuscules, chiffres et symboles
   - Ne le réutilisez pas ailleurs
   - Ne l'oubliez pas (il n'y a pas de récupération possible)

2. **Sauvegarde**
   - Exportez régulièrement vos données
   - Conservez plusieurs copies du fichier
   - Stockez les sauvegardes en lieu sûr

## FAQ

**Q: Que se passe-t-il si j'oublie mon mot de passe maître ?**  
R: Il n'y a malheureusement aucun moyen de récupérer vos données. Le chiffrement est local et il n'existe pas de "porte dérobée".

**Q: Mes données sont-elles synchronisées en ligne ?**  
R: Non, l'application fonctionne entièrement en local. Vous devez gérer manuellement vos sauvegardes.

**Q: Comment partager des mots de passe en équipe ?**  
R: L'application est conçue pour un usage personnel. Pour un usage en équipe, privilégiez une solution professionnelle.

---

© 2024 Gestionnaire de Mots de Passe - Tous droits réservés 