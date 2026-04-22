# 🛡️ CyberDashboard — Threat Intelligence

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-FTS5-003B57?logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/Licence-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)

Dashboard de surveillance des menaces cyber en temps réel. Agrège automatiquement les données de **5 sources publiques** (CVE, malwares, phishing) et les présente dans une interface sombre style terminal.

---

## ✨ Fonctionnalités

- **Flux live** — ticker de menaces mis à jour en temps réel
- **Multi-sources** — NVD, CISA KEV, PhishTank, URLhaus, MalwareBazaar
- **Recherche plein texte** — indexation FTS5 SQLite pour des recherches instantanées
- **Filtrage avancé** — par type (Vulnérabilité / Malware / Phishing) et score CVSS
- **Traduction FR** — traduction automatique des fiches en français via `deep-translator`
- **API REST** — backend FastAPI avec documentation Swagger intégrée
- **Notifications** — alertes navigateur pour les nouvelles menaces critiques
- **Démarrage en 1 clic** — script `start.bat` qui installe les dépendances et lance tout

---

## 📸 Aperçu

> *Ajoute ici une capture d'écran du dashboard*

---

## 🗂️ Structure du projet

```
dashboard-cyber/
├── backend/
│   ├── main.py          # API FastAPI (endpoints REST)
│   ├── database.py      # Couche SQLite + FTS5
│   ├── models.py        # Modèles Pydantic
│   ├── updater.py       # Collecte delta depuis les 5 sources
│   ├── translator.py    # Traduction automatique FR
│   ├── seed.py          # Données de démonstration
│   └── requirements.txt
├── frontend/
│   ├── index.html       # Interface utilisateur
│   ├── style.css        # Thème sombre terminal
│   └── app.js           # Logique frontend (vanilla JS)
├── start.bat            # Lanceur Windows (installation + démarrage)
├── diagnostic.bat       # Script de diagnostic en cas de problème
├── .env                 # Clés API (non versionné)
└── database.db          # Base SQLite (non versionnée)
```

---

## 🚀 Installation & Démarrage

### Prérequis

- **Python 3.10+** — [télécharger](https://www.python.org/downloads/) *(cocher "Add Python to PATH")*
- Un navigateur web moderne

### Démarrage rapide (Windows)

```bat
double-clic sur start.bat
```

Le script va automatiquement :
1. Vérifier la présence de Python
2. Installer les dépendances (`fastapi`, `uvicorn`, `httpx`, etc.)
3. Initialiser la base de données avec des données de démonstration
4. Lancer le backend sur `http://127.0.0.1:8000`
5. Ouvrir le dashboard dans le navigateur

### Démarrage manuel

```bash
cd backend
pip install -r requirements.txt
python seed.py          # optionnel : données de démo
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Puis ouvrir `frontend/index.html` dans le navigateur.

---

## ⚙️ Configuration

Crée un fichier `.env` à la racine du projet pour configurer les clés API optionnelles :

```env
# Clé NVD (recommandée pour éviter le rate-limiting)
# Obtenir gratuitement sur : https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=ta_cle_nvd_ici

# Clé PhishTank (optionnelle)
# Obtenir sur : https://www.phishtank.com/api_info.php
PHISHTANK_API_KEY=ta_cle_phishtank_ici

# Score CVSS minimum pour les CVE importées (défaut : 7.0)
CVSS_MIN=7.0
```

> Sans clés API, le dashboard fonctionne avec les sources publiques sans authentification (rate-limiting possible sur NVD).

---

## 🌐 Sources de données

| Source | Type | Description |
|---|---|---|
| [NVD (NIST)](https://nvd.nist.gov/) | CVE | Base officielle des vulnérabilités américaines |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVE exploitées | Vulnérabilités activement exploitées en conditions réelles |
| [PhishTank](https://www.phishtank.com/) | Phishing | URLs de phishing actives et vérifiées |
| [URLhaus](https://urlhaus.abuse.ch/) | Malware | URLs servant à distribuer des malwares |
| [MalwareBazaar](https://bazaar.abuse.ch/) | Malware | Samples de malwares récents (SHA256) |

---

## 📡 API REST

Le backend expose les endpoints suivants (documentation complète sur `/docs`) :

| Méthode | Endpoint | Description |
|---|---|---|
| `GET` | `/vulnerabilities` | Liste paginée avec recherche et filtres |
| `GET` | `/vulnerabilities/{id}` | Détail d'une entrée |
| `GET` | `/stats` | Statistiques globales (total, par type, par sévérité) |
| `GET` | `/recent-alerts` | Dernières menaces pour le ticker |
| `GET` | `/update-check` | Déclenche une mise à jour delta depuis toutes les sources |
| `GET` | `/translate/{id}` | Traduit une fiche en français |
| `GET` | `/translate-all` | Traduit un batch d'entrées non traduites |
| `GET` | `/health` | Santé de l'API |

---

## 🔧 Dépannage

En cas de problème au démarrage, lancer `diagnostic.bat` pour un rapport détaillé.

Erreurs fréquentes :
- **Python introuvable** → réinstaller Python en cochant "Add to PATH"
- **Port 8000 occupé** → fermer l'application qui utilise ce port
- **Rate-limiting NVD** → ajouter une clé `NVD_API_KEY` dans `.env`

---

## 📄 Licence

Ce projet est distribué sous licence **MIT**. Voir le fichier [LICENSE](LICENSE) pour plus de détails.
