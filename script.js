/*******************/
/* script.js       */
/*******************/

// =====================
// Variables globales
// =====================
let masterKey = null;                // Clé AES-GCM dérivée du mot de passe maître
let masterPassword = "";             // Mot de passe maître (juste pour info/redérivation)
let currentData = [];                // Tableau d'entrées : { id, service, login, password, category, url, creationDate, expirationDate, notes, otp }
let currentFileImported = false;     // Savoir si on a importé un fichier
let currentCategory = null;          // Catégorie sélectionnée (null = toutes)
let currentSalt = null;              // Le salt utilisé pour dériver la clé
let categories = new Set();          // Pour stocker toutes les catégories, même vides
let isGridView = false;

// Ajouter ces variables globales au début du fichier
let currentVaultVersion = null;  // Version actuelle du Vault
let savedVaultVersion = null;    // Version de la dernière sauvegarde

// Ajouter ces variables globales au début du fichier
let autoLockTimeout = null;
let lastActivityTime = Date.now();
let isLocked = false;

// Ajouter ces variables globales au début du fichier
let currentSettings = {
  language: 'fr',
  theme: 'light',
  autoLock: false,
  lockTimeout: 5,
  doubleAuth: false
};

// Sélecteurs
const welcomeScreen = document.getElementById("welcome-screen");
const appScreen = document.getElementById("app-screen");
const importSection = document.getElementById("import-section");
const newSessionSection = document.getElementById("new-session-section");
const fileInput = document.getElementById("file-input");
const btnDecrypter = document.getElementById("btn-decrypter");
const importError = document.getElementById("import-error");
const masterPassImp = document.getElementById("master-password-import");
const btnNewSession = document.getElementById("btn-new-session");
const dropZone = document.querySelector(".drop-zone");
const welcomeButtons = document.querySelector(".welcome-buttons");
const separator = document.querySelector(".separator");

const btnCreateSession  = document.getElementById("btn-create-session");
const newSessionError   = document.getElementById("new-session-error");
const masterPassNew     = document.getElementById("master-password-new");

const btnExport       = document.getElementById("btn-export");

const categoryList    = document.getElementById("category-list");
const btnAddCategory  = document.getElementById("btn-add-category");
const newCategoryName = document.getElementById("new-category-name");

const passwordList    = document.getElementById("password-list");
const btnAddPassword  = document.getElementById("btn-add-password");
const currentCategoryTitle = document.getElementById("current-category-title");

// Variables globales
const btnImport = document.getElementById("btn-import");

// Ajouter les variables pour le tri
let sortField = "service";
let sortAscending = true;

// Ajouter au début du fichier avec les autres variables globales
const CATEGORY_COLORS = {
  'blue': '#4a90e2',
  'green': '#27ae60',
  'purple': '#9b59b6',
  'orange': '#f39c12',
  'red': '#e74c3c',
  'teal': '#16a085',
  'pink': '#e84393',
  'brown': '#795548'
};

// Ajouter avec les autres sélecteurs au début du fichier
const btnAnalyze = document.getElementById("btn-analyze");
const analyzeModal = document.getElementById("analyze-modal");
const analyzeOverlay = document.getElementById("analyze-overlay");
const btnCloseAnalyze = document.getElementById("btn-close-analyze");
const analyzeLoading = document.querySelector(".analyze-loading");
const analyzeResults = document.querySelector(".analyze-results");

// Ajouter ces variables globales au début du fichier
let lastExportedData = null;  // Pour stocker la dernière version exportée des données

// =====================
// Événements de l'écran d'accueil
// =====================

// Bouton "Importer un fichier chiffré"
btnImport.addEventListener("click", () => {
  importSection.classList.remove("hidden");
  newSessionSection.classList.add("hidden");
});

// Bouton "Créer une nouvelle session"
btnNewSession.addEventListener("click", () => {
  newSessionSection.classList.remove("hidden"); // Modifié pour toujours afficher
  importSection.classList.add("hidden"); // Ajouté pour cacher la section import
});

// Garder uniquement cette version de initializeFileUpload()
function initializeFileUpload() {
  const dropZone = document.querySelector(".drop-zone");
  const fileInput = document.getElementById("file-input");

  // Empêcher le comportement par défaut
  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, e => {
      e.preventDefault();
      e.stopPropagation();
    });
  });

  // Gérer le drag & drop
  dropZone.addEventListener('dragenter', () => dropZone.classList.add('drag-over'));
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', (e) => {
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) handleFileUpload(file);
  });

  // Gérer la sélection de fichier
  fileInput.addEventListener('change', (e) => {
    if (e.target.files[0]) handleFileUpload(e.target.files[0]);
  });
}

// Garder uniquement cette version complète de handleFileUpload()
async function handleFileUpload(fileOrContent) {
  const importError = document.getElementById("import-error");
  const fileInput = document.getElementById("file-input");
  const dropZone = document.querySelector(".drop-zone");
  
  try {
    let fileContent;
    let fileName;

    // Cas 1: Upload via double-clic (le fichier est un objet avec content et name)
    if (typeof fileOrContent === 'object' && fileOrContent.content && fileOrContent.name) {
      fileContent = fileOrContent.content;
      fileName = fileOrContent.name;
    }
    // Cas 2: Upload via File object (drag & drop ou sélection manuelle)
    else if (fileOrContent instanceof File) {
      if (!fileOrContent.name.endsWith('.html')) {
        throw new Error("Seuls les fichiers HTML sont acceptés");
      }
      fileName = fileOrContent.name;
      fileContent = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(reader.error);
        reader.readAsText(fileOrContent);
      });
    } else {
      throw new Error("Format de fichier non supporté");
    }

    // Si le contenu commence par "data:text/html" (cas du double-clic)
    if (fileContent.startsWith('data:text/html')) {
      try {
        const base64Content = fileContent.split(',')[1];
        fileContent = atob(base64Content);
      } catch (error) {
        console.error('Erreur lors du décodage base64:', error);
        throw new Error("Erreur lors du décodage du fichier");
      }
    }

    // Extraire le contenu JSON du fichier HTML
    const match = fileContent.match(/const keyFileContent = ({.*?});/s);
    if (!match) {
      throw new Error("Format de fichier HTML invalide");
    }

    const keyFileContent = JSON.parse(match[1]);

    // Vérifier le type de fichier
    if (keyFileContent.fileType !== "password-manager-key") {
      throw new Error("Ce n'est pas un fichier de vault valide");
    }

    // Mettre à jour l'interface
    dropZone.querySelector('p').textContent = `Fichier sélectionné : ${fileName}`;
    importError.textContent = "";

    // Stocker les données pour le déchiffrement
    fileInput.dataset.keyContent = JSON.stringify(keyFileContent);
    
    // Focus sur le champ de mot de passe
    document.getElementById("master-password-import").focus();

  } catch (error) {
    console.error('Erreur lors du traitement du fichier:', error);
    importError.textContent = error.message || "Format de fichier invalide";
    dropZone.querySelector('p').textContent = "Glissez votre fichier ici ou";
    fileInput.value = '';
    delete fileInput.dataset.keyContent;
  }
}

// Fonction de déchiffrement modifiée
async function decryptVault(password) {
  const importError = document.getElementById("import-error");
  const fileInput = document.getElementById("file-input");

  try {
    // Récupérer les données stockées
    const keyContent = JSON.parse(fileInput.dataset.keyContent);

    // Dériver la clé
    currentSalt = base64ToArrayBuffer(keyContent.salt);
    const key = await deriveKeyFromPassword(password, currentSalt);

    // Déchiffrer
    const iv = base64ToArrayBuffer(keyContent.iv);
    const ciphertext = base64ToArrayBuffer(keyContent.ciphertext);

    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );

    const decodedStr = new TextDecoder().decode(decrypted);
    const dataObj = JSON.parse(decodedStr);

    // Mettre à jour les données globales
    currentData = dataObj.entries || [];
    masterKey = key;
    masterPassword = password;
    currentFileImported = true;
    currentVaultVersion = keyContent.versionCode;
    savedVaultVersion = keyContent.versionCode;

    // Restaurer les paramètres s'ils existent
    if (dataObj.settings) {
      currentSettings = dataObj.settings;
      applySettings();
    }

    // Restaurer les couleurs des catégories
    if (dataObj.categoryColors) {
      categoryColors = new Map(Object.entries(dataObj.categoryColors));
    }

    return true;
  } catch (error) {
    console.error('Erreur de déchiffrement:', error);
    return false;
  }
}

// Modifier le gestionnaire du bouton Déchiffrer
btnDecrypter.addEventListener("click", async () => {
  const importError = document.getElementById("import-error");
  const password = document.getElementById("master-password-import").value.trim();
  
  if (!password) {
    importError.textContent = "Veuillez saisir votre mot de passe maître.";
    return;
  }

  if (!document.getElementById("file-input").dataset.keyContent) {
    importError.textContent = "Veuillez d'abord sélectionner un fichier.";
    return;
  }

  const success = await decryptVault(password);
  
  if (success) {
    importError.textContent = "";
    showAppScreen();
  } else {
    importError.textContent = "Échec du déchiffrement. Mot de passe incorrect ou fichier invalide.";
  }
});

// Ajouter la gestion du fichier en localStorage au chargement
document.addEventListener('DOMContentLoaded', () => {
  initializeFileUpload();

  const pendingKeyFile = localStorage.getItem('pendingKeyFile');
  if (pendingKeyFile) {
    try {
      const keyData = JSON.parse(pendingKeyFile);
      
      if (keyData.fileType === "password-manager-key") {
        // Afficher la section d'import
        importSection.classList.remove("hidden");
        newSessionSection.classList.add("hidden");
        
        // Utiliser le versionCode pour créer le nom de fichier réel
        const fileName = `passwords_${keyData.versionCode}.html`;
        
        // Créer le contenu HTML simulé
        const htmlContent = `
          <!DOCTYPE html>
          <html>
          <script>
            const keyFileContent = ${JSON.stringify(keyData)};
          </script>
          </html>
        `;
        
        // Créer un objet qui contient à la fois le contenu et le nom du fichier
        const fileData = {
          content: htmlContent,
          name: fileName
        };
        
        // Traiter le fichier
        handleFileUpload(fileData);
      }
    } catch (error) {
      console.error("Erreur lors du chargement du fichier en attente:", error);
    }
    
    localStorage.removeItem('pendingKeyFile');
  }
});

// Bouton "Créer une nouvelle session"
btnCreateSession.addEventListener("click", async () => {
  const password = masterPassNew.value.trim();
  if (!password) {
    newSessionError.textContent = "Veuillez saisir un mot de passe maître.";
    return;
  }
  
  // Vérifier la force du mot de passe
  if (!evaluateMasterPassword(password)) {
    newSessionError.textContent = "Le mot de passe maître n'est pas assez fort.";
    return;
  }

  newSessionError.textContent = "";

  // Génère un salt aléatoire et dérive la clé
  currentSalt = generateRandomSalt(16);
  const key = await deriveKeyFromPassword(password, currentSalt);
  masterKey = key;
  masterPassword = password;

  currentData = []; 
  currentFileImported = false;

  showAppScreen();
});

// Ajouter les event listeners pour la touche Entrée
masterPassImp.addEventListener("keyup", (event) => {
  if (event.key === "Enter") {
    btnDecrypter.click();
  }
});

masterPassNew.addEventListener("keyup", (event) => {
  if (event.key === "Enter") {
    btnCreateSession.click();
  }
});

// =====================
// Écran principal
// =====================
btnAddCategory.addEventListener("click", () => {
  const name = newCategoryName.value.trim();
  if (!name) return;
  
  // Ajouter la catégorie
  categories.add(name);
  newCategoryName.value = '';
  
  // Mettre à jour l'interface
  updateCategorySelect();
  renderCategories();
  
  // Afficher une notification
  showNotification('Nouvelle catégorie ajoutée');
});

btnAddPassword.addEventListener("click", () => {
  // Cette version-ci est la version finale (avec date par défaut).
  document.getElementById('password-form').reset();
  
  // Définir la date de création par défaut (aujourd'hui)
  const today = new Date().toISOString().split('T')[0];
  document.getElementById('creation-date').value = today;
  
  // Afficher la modale
  document.getElementById('add-password-overlay').classList.add('show');
  document.getElementById('add-password-modal').classList.add('show');
  
  // S'assurer que l'onglet "Mot de passe" est actif
  document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
  document.querySelector('.tab-button[data-tab="password"]').classList.add('active');
  
  document.querySelectorAll('.tab-content').forEach(content => content.classList.add('hidden'));
  document.getElementById('password-tab').classList.remove('hidden');
  
  // Focus sur le premier champ
  document.getElementById('service-input').focus();
});

btnExport.addEventListener("click", async () => {
  await handleExport();
});

// =====================
// Fonctions principales
// =====================
function showAppScreen() {
  welcomeScreen.classList.add("hidden");
  appScreen.classList.remove("hidden");
  
  // Mettre à jour les catégories depuis les données existantes
  currentData.forEach(entry => {
    if (entry.category) {
      categories.add(entry.category);
    }
  });
  
  updateCategorySelect();
  renderCategories();
  renderPasswords();
  
  initAutoLock();
  autoSave();
}

/**
 * Gère l'export (chiffrement + téléchargement du JSON)
 */
async function handleExport() {
  try {
    if (!masterKey) {
      showNotification("Erreur : Clé non disponible", true);
      return;
    }

    if (!currentData || currentData.length === 0) {
      showNotification("Aucune donnée à exporter", true);
      return;
    }

    // Vérifier si les données ont changé depuis le dernier import/export
    if (
      lastExportedData && 
        JSON.stringify(currentData) === JSON.stringify(lastExportedData) &&
      currentVaultVersion === savedVaultVersion
    ) {
      showNotification("Aucune modification depuis le dernier export", true);
      return;
    }

    // Générer une nouvelle version si nécessaire
    if (!currentVaultVersion) {
      currentVaultVersion = generateVersionCode();
    } else if (currentVaultVersion === savedVaultVersion) {
      const [datePart, versionNumber] = currentVaultVersion.split('-');
      const newVersionNumber = (parseInt(versionNumber) + 1).toString().padStart(2, '0');
      currentVaultVersion = `${datePart}-${newVersionNumber}`;
    }

    // On va chiffrer currentData et les paramètres
    const plainObj = {
      entries: currentData,
      version: currentVaultVersion,
      settings: currentSettings,
      categoryColors: Object.fromEntries(categoryColors)
    };
    const plainStr = JSON.stringify(plainObj);

    // Création d'un IV aléatoire
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // Conversion en ArrayBuffer
    const encodedPlain = new TextEncoder().encode(plainStr);

    // Chiffrement AES-GCM
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      masterKey,
      encodedPlain
    );

    const exportObj = {
      salt: arrayBufferToBase64(currentSalt),
      iv: arrayBufferToBase64(iv),
      ciphertext: arrayBufferToBase64(ciphertext),
      timestamp: new Date().toISOString(),
      versionCode: currentVaultVersion,
      siteUrl: window.location.href,
      fileType: "password-manager-key",
      entryCount: currentData.length
    };

    const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Redirection vers le gestionnaire de mots de passe</title>
  <script>
    const keyFileContent = ${JSON.stringify(exportObj)};
    
    window.onload = function() {
      const siteUrl = "${window.location.href}";
      window.location.href = siteUrl;
      localStorage.setItem('pendingKeyFile', JSON.stringify(keyFileContent));
    }
  </script>
</head>
<body>
  <h1>Redirection vers le gestionnaire de mots de passe...</h1>
  <p>Version du fichier : ${currentVaultVersion}</p>
  <p>Nombre d'entrées : ${currentData.length}</p>
</body>
</html>`;

    // Simplifier le nom du fichier pour n'avoir que le code version
    const fileName = `passwords_${currentVaultVersion}.html`;

    downloadFile(htmlContent, fileName, "text/html");

    // Après un export réussi
    savedVaultVersion = currentVaultVersion;
    lastExportedData = JSON.parse(JSON.stringify(currentData));
    
    updateDataSection();
    showNotification(`Fichier exporté : ${fileName}`, false);

  } catch (err) {
    console.error('Erreur lors de l\'export:', err);
    showNotification("Erreur lors de l'export", true);
  }
}

/**
 * Lit un fichier en texte (FileReader)
 */
function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (event) => {
      let content = event.target.result;
      
      // Si le contenu commence par "data:text/html" (cas du double-clic)
      if (content.startsWith('data:text/html')) {
        try {
          // Extraire le contenu réel après le header base64
          const base64Content = content.split(',')[1];
          content = atob(base64Content);
        } catch (error) {
          console.error('Erreur lors du décodage base64:', error);
          reject(error);
          return;
        }
      }
      
      resolve(content);
    };
    reader.onerror = (error) => {
      reject(error);
    };
    
    // Si le fichier est déjà sous forme de texte (cas du double-clic)
    if (typeof file === 'string') {
      resolve(file);
    } else {
      reader.readAsText(file);
    }
  });
}

/**
 * Télécharge une chaîne sous forme de fichier
 */
function downloadFile(text, fileName, contentType) {
  const blob = new Blob([text], { type: contentType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Génère un salt aléatoire (ArrayBuffer)
 */
function generateRandomSalt(size) {
  const salt = new Uint8Array(size);
  window.crypto.getRandomValues(salt);
  return salt.buffer;
}

/**
 * Dérive une clé AES-GCM 256 bits depuis un password + salt, via PBKDF2
 */
async function deriveKeyFromPassword(password, saltBuffer) {
  const enc = new TextEncoder();
  const passKey = enc.encode(password);

  const baseKey = await window.crypto.subtle.importKey(
    "raw",
    passKey,
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBuffer,
      iterations: 100000,
      hash: "SHA-256"
    },
    baseKey,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  );
}

// =====================
// Conversion base64
// =====================
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// =====================
// Gestion UI des catégories
// =====================
function renderCategories() {
  categoryList.innerHTML = "";

  // "Toutes les entrées"
  const liAll = document.createElement("li");
  liAll.classList.add("category-item");
  
  const allContentDiv = document.createElement("div");
  allContentDiv.classList.add("category-content");
  
  const allNameSpan = document.createElement("span");
  allNameSpan.textContent = "Toutes les entrées";
  
  allContentDiv.appendChild(allNameSpan);
  liAll.appendChild(allContentDiv);

  if (!currentCategory) {
    liAll.classList.add("active");
  }

  liAll.addEventListener("click", () => {
    currentCategory = null;
    renderCategories();
    renderPasswords();
  });
  
  categoryList.appendChild(liAll);

  // Les catégories existantes
  const sortedCategories = Array.from(new Set([...categories, ...currentData.map(item => item.category)].filter(c => c))).sort();

  sortedCategories.forEach(cat => {
    const li = document.createElement("li");
    li.classList.add("category-item");
    
    const contentDiv = document.createElement("div");
    contentDiv.classList.add("category-content");
    
    const nameSpan = document.createElement("span");
    nameSpan.textContent = cat;
    const color = getCategoryColor(cat);
    if (color) {
      nameSpan.style.color = color;
      li.style.borderLeft = `4px solid ${color}`;
    }
    
    const editBtn = document.createElement("button");
    editBtn.classList.add("btn-edit-category");
    editBtn.innerHTML = '<i class="fas fa-pen"></i>';
    editBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      showCategoryEditModal(cat);
    });

    if (cat === currentCategory) {
      li.classList.add("active");
    }

    li.addEventListener("click", () => {
      currentCategory = cat;
      renderCategories();
      renderPasswords();
    });

    contentDiv.appendChild(nameSpan);
    contentDiv.appendChild(editBtn);
    li.appendChild(contentDiv);
    categoryList.appendChild(li);
  });
}

/**
 * Ajoute une catégorie dans l'UI (si elle n'existe pas déjà)
 */
function addCategoryToUI(name) {
  categories.add(name);
  currentCategory = name;
  updateCategorySelect();
  renderCategories();
  renderPasswords();
}

// =====================
// Gestion UI des mots de passe
// =====================
function renderPasswords() {
  passwordList.innerHTML = "";

  if (currentCategory) {
    currentCategoryTitle.textContent = `Catégorie : ${currentCategory}`;
  } else {
    currentCategoryTitle.textContent = "Toutes les entrées";
  }

  let filtered = currentData;
  if (currentCategory) {
    filtered = filtered.filter(item => item.category === currentCategory);
  }

  filtered = filterPasswords(filtered);
  filtered = sortPasswords(filtered);

  filtered.forEach((entry) => {
    const li = document.createElement("li");
    li.classList.add("password-item");
    li.dataset.id = entry.id;

    // Ajouter un indicateur OTP si présent
    const serviceSpan = document.createElement("span");
    serviceSpan.classList.add("password-service");
    serviceSpan.innerHTML = `
      <div class="field-header">
        <i class="fas fa-globe field-icon"></i>
        ${entry.service}
      </div>
    `;

    const loginSpan = document.createElement("span");
    loginSpan.classList.add("password-login");
    loginSpan.innerHTML = `
      <div class="field-header">
        <i class="fas fa-user field-icon"></i>
        ${entry.login}
      </div>
    `;

    const pwdContainer = document.createElement("div");
    pwdContainer.classList.add("password-values");

    const pwdSpan = document.createElement("span");
    pwdSpan.classList.add("password-value");
    pwdSpan.innerHTML = `
      <div class="field-header">
        <i class="fas fa-lock field-icon"></i>
        <span class="password-text">********</span>
      </div>
    `;

    // Pour le champ mot de passe
    pwdSpan.addEventListener('click', () => {
      navigator.clipboard.writeText(entry.password)
        .then(() => showNotification('Mot de passe copié !'))
        .catch(() => showNotification('Échec de la copie', true));
    });

    // Pour le champ OTP (s'il existe)
    if (entry.otp) {
      const otpSpan = document.createElement("span");
      otpSpan.classList.add("password-value", "otp-code");
      const code = generateTOTP(entry.otp.secret); // Générer le code immédiatement
      otpSpan.innerHTML = `
        <div class="field-header">
          <i class="fas fa-clock field-icon"></i>
          <span class="otp-display" data-secret="${entry.otp.secret}">${code}</span>
          <div class="otp-timer"></div>
        </div>
      `;
      
      // Ajouter l'event listener pour la copie au clic
      otpSpan.addEventListener('click', () => {
        const currentCode = generateTOTP(entry.otp.secret); // Générer un nouveau code au moment du clic
        navigator.clipboard.writeText(currentCode)
          .then(() => showNotification('Code 2FA copié !'))
          .catch(() => showNotification('Échec de la copie', true));
      });
      
      pwdContainer.appendChild(otpSpan);
      pwdContainer.appendChild(pwdSpan);
      pwdContainer.classList.add('with-otp');
    } else {
      pwdContainer.appendChild(pwdSpan);
    }

    // Boutons avec icônes
    const btnReveal = document.createElement("button");
    btnReveal.classList.add("btn-reveal");
    btnReveal.innerHTML = '<i class="fas fa-eye"></i>';
    
    const btnEdit = document.createElement("button");
    btnEdit.classList.add("btn-edit");
    btnEdit.innerHTML = '<i class="fas fa-pen"></i>';
    
    const btnDelete = document.createElement("button");
    btnDelete.classList.add("btn-delete");
    btnDelete.innerHTML = '<i class="fas fa-trash"></i>';

    // Ajouter le bouton favori
    const btnFavorite = document.createElement("button");
    btnFavorite.classList.add("btn-favorite");
    if (entry.favorite) {
      btnFavorite.classList.add("active");
    }
    btnFavorite.innerHTML = `<i class="fas fa-star"></i>`;
    
    btnFavorite.addEventListener("click", () => {
      entry.favorite = !entry.favorite;
      btnFavorite.classList.toggle("active");
      showNotification(entry.favorite ? "Ajouté aux favoris" : "Retiré des favoris");
      
      // Réorganiser et réafficher la liste
      sortPasswords(filtered);
      renderPasswords();
    });

    // Événements des boutons
    btnReveal.addEventListener("click", () => {
      const pwdField = pwdSpan.querySelector('.field-header');
      if (pwdField.querySelector('.password-text').textContent === "********") {
        // Révéler le mot de passe
        pwdField.querySelector('.password-text').textContent = entry.password;
        btnReveal.innerHTML = '<i class="fas fa-eye-slash"></i><div class="circular-progress"></div>';
        btnReveal.classList.add('revealing');
        
        // Programmer le masquage automatique après 5 secondes
        setTimeout(() => {
          pwdField.querySelector('.password-text').textContent = "********";
          btnReveal.innerHTML = '<i class="fas fa-eye"></i>';
          btnReveal.classList.remove('revealing');
        }, 5000);
      } else {
        // Masquer le mot de passe immédiatement
        pwdField.querySelector('.password-text').textContent = "********";
        btnReveal.innerHTML = '<i class="fas fa-eye"></i>';
        btnReveal.classList.remove('revealing');
      }
    });

    btnEdit.addEventListener("click", () => {
      editPassword(entry);
    });

    btnDelete.addEventListener("click", () => {
      if (confirm("Voulez-vous vraiment supprimer ce mot de passe ?")) {
        currentData = currentData.filter(e => e.id !== entry.id);
        incrementVaultVersion();
        renderPasswords();
      }
    });

    // Créer un conteneur pour les boutons
    const buttonGroup = document.createElement("div");
    buttonGroup.classList.add("button-group");

    // Ajouter les boutons au groupe (ajouter le favori en premier)
    buttonGroup.appendChild(btnFavorite);
    buttonGroup.appendChild(btnReveal);
    buttonGroup.appendChild(btnEdit);
    buttonGroup.appendChild(btnDelete);

    // Assemblage
    li.appendChild(serviceSpan);
    li.appendChild(loginSpan);
    li.appendChild(pwdContainer);
    li.appendChild(buttonGroup);
    
    passwordList.appendChild(li);

    applyPasswordItemStyles(li, entry);
  });

  // Au lieu de l'ancien updatePasswordCount(), on se base maintenant sur updateDataSection()
  updateDataSection();
}

/**
 * Réordonne currentData suite à un drop (placeholder si besoin)
 */
function reorderEntries(draggedId, targetId) {
  if (draggedId === targetId) return;
  
  const draggedIndex = currentData.findIndex(e => e.id === draggedId);
  const targetIndex = currentData.findIndex(e => e.id === targetId);
  
  if (draggedIndex === -1 || targetIndex === -1) return;
  
  const [draggedItem] = currentData.splice(draggedIndex, 1);
  const newTargetIndex = currentData.findIndex(e => e.id === targetId);
  currentData.splice(newTargetIndex, 0, draggedItem);
}

// Ajouter cette nouvelle fonction pour gérer les notifications
function showNotification(message = "Mot de passe copié !", isError = false) {
  const notification = document.getElementById("copy-notification");
  
  // Réinitialiser l'animation en retirant la classe
  notification.classList.remove("show");
  
  // Force le navigateur à recalculer le style pour réinitialiser l'animation
  void notification.offsetWidth;
  
  // Mettre à jour le contenu et le style
  notification.textContent = message;
  notification.style.backgroundColor = isError ? "#dc3545" : "#28a745";
  
  // Afficher la notification
  notification.classList.add("show");
  
  // Supprimer la notification après 2 secondes
  const timeoutId = setTimeout(() => {
    notification.classList.remove("show");
  }, 2000);
  
  // Stocker l'ID du timeout sur l'élément pour pouvoir l'annuler si nécessaire
  notification.dataset.timeoutId = timeoutId;
}

function clearNotifications() {
  const notifications = document.querySelectorAll('.notification');
  notifications.forEach(notification => {
    if (notification.dataset.timeoutId) {
      clearTimeout(Number(notification.dataset.timeoutId));
    }
    notification.classList.remove("show");
  });
}

// =====================
// Utilitaires divers
// =====================
function generateId() {
  return "id-" + Math.random().toString(36).substr(2, 9);
}

// Gestion du formulaire d'ajout/édition
document.getElementById('password-form').addEventListener('submit', (e) => {
  e.preventDefault();
  
  const editId = e.target.dataset.editId;
  const service = document.getElementById('service-input').value.trim();
  const login = document.getElementById('login-input').value.trim();
  const pwd = document.getElementById('password-input').value.trim();
  const category = document.getElementById('category-select').value;
  const otpSecret = document.getElementById('otp-secret').value.trim().toUpperCase();
  
  // Champs ajoutés
  const url = document.getElementById('url-input').value.trim();
  const creationDate = document.getElementById('creation-date').value;
  const expirationDate = document.getElementById('expiration-date').value;
  const notes = document.getElementById('notes-input').value.trim();

  if (!service || !login || !pwd) {
    showNotification('Veuillez remplir tous les champs obligatoires', true);
    return;
  }

  const newEntry = {
    id: editId || generateId(),
    service,
    login,
    password: pwd,
    category,
    url,
    creationDate,
    expirationDate,
    notes,
    favorite: false,
    otp: otpSecret ? {
      secret: otpSecret,
      type: 'totp',
      digits: 6,
      period: 30
    } : null
  };

  if (editId) {
    // Mode édition
    const index = currentData.findIndex(e => e.id === editId);
    if (index !== -1) {
      currentData[index] = { ...currentData[index], ...newEntry };
    }
    delete e.target.dataset.editId;
  } else {
    // Mode ajout
    currentData.push(newEntry);
  }

  // Fermer la modale et réinitialiser
  document.getElementById('add-password-overlay').classList.remove('show');
  document.getElementById('add-password-modal').classList.remove('show');
  e.target.reset();
  
  // Réinitialiser l'aperçu OTP
  document.querySelector('.otp-preview .otp-display').textContent = '';
  
  // Revenir à l'onglet mot de passe
  document.querySelector('.tab-button[data-tab="password"]').click();
  
  // Réinitialiser le bouton submit
  const submitBtn = e.target.querySelector('button[type="submit"]');
  submitBtn.textContent = 'Ajouter';
  
  // Mettre à jour l'affichage
  renderPasswords();
  showNotification('Mot de passe enregistré avec succès');

  // Incrémenter la version après chaque modification
  incrementVaultVersion();
  
  updateDataSection();
});

document.getElementById('btn-cancel-password').addEventListener('click', () => {
  document.getElementById('add-password-overlay').classList.remove('show');
  document.getElementById('add-password-modal').classList.remove('show');
  document.getElementById('password-form').reset();
  
  // Réinitialiser l'onglet OTP
  document.getElementById('otp-secret').value = '';
  document.querySelector('.otp-preview .otp-display').textContent = '';
  delete document.getElementById('password-form').dataset.otpSecret;
  
  // Revenir à l'onglet mot de passe
  document.querySelector('.tab-button[data-tab="password"]').click();
});

// Ajouter cette fonction pour mettre à jour la catégorie d'un mot de passe
function updatePasswordCategory(passwordId, newCategory) {
  const passwordEntry = currentData.find(entry => entry.id === passwordId);
  if (passwordEntry) {
    passwordEntry.category = newCategory;
    showNotification(`Catégorie mise à jour : ${newCategory || 'Toutes les entrées'}`);
    renderPasswords();
    renderCategories();
  }
}

// Recherche
const searchInput = document.getElementById("search-input");
const searchFilter = document.getElementById("search-filter");

searchInput.addEventListener("input", () => {
  renderPasswords();
});

searchFilter.addEventListener("change", () => {
  renderPasswords();
});

function filterPasswords(passwords) {
  const searchText = searchInput.value.toLowerCase();
  const filterType = searchFilter.value;

  if (!searchText) return passwords;

  return passwords.filter(entry => {
    switch (filterType) {
      case "service":
        return entry.service.toLowerCase().includes(searchText);
      case "login":
        return entry.login.toLowerCase().includes(searchText);
      default:
        return (
          entry.service.toLowerCase().includes(searchText) ||
          entry.login.toLowerCase().includes(searchText)
        );
    }
  });
}

// Tri
function sortPasswords(passwords) {
  return passwords.sort((a, b) => {
    // D'abord trier par favoris
    if (a.favorite && !b.favorite) return -1;
    if (!a.favorite && b.favorite) return 1;
    
    // Ensuite appliquer le tri standard
    let comparison = 0;
    switch (sortField) {
      case "service":
        comparison = a.service.localeCompare(b.service);
        break;
      case "login":
        comparison = a.login.localeCompare(b.login);
        break;
      case "date":
        comparison = a.id.localeCompare(b.id);
        break;
    }
    return sortAscending ? comparison : -comparison;
  });
}

document.getElementById("sort-select").addEventListener("change", (e) => {
  sortField = e.target.value;
  renderPasswords();
});

document.getElementById("btn-sort-direction").addEventListener("click", () => {
  sortAscending = !sortAscending;
  const icon = document.querySelector("#btn-sort-direction i");
  icon.className = sortAscending ? 
    "fas fa-sort-amount-down" : 
    "fas fa-sort-amount-up";
  renderPasswords();
});

// Édition
function editPassword(entry) {
  // Remplir le formulaire avec les données existantes
  document.getElementById('service-input').value = entry.service;
  document.getElementById('login-input').value = entry.login;
  document.getElementById('password-input').value = entry.password;
  document.getElementById('category-select').value = entry.category || '';
  
  // Remplir les nouveaux champs
  document.getElementById('url-input').value = entry.url || '';
  document.getElementById('creation-date').value = entry.creationDate || '';
  document.getElementById('expiration-date').value = entry.expirationDate || '';
  document.getElementById('notes-input').value = entry.notes || '';
  
  if (entry.otp) {
    document.getElementById('otp-secret').value = entry.otp.secret;
  }
  
  // Modifier le bouton submit
  const submitBtn = document.querySelector('#password-form button[type="submit"]');
  submitBtn.textContent = 'Modifier';
  
  // Modifier le comportement du formulaire
  const form = document.getElementById('password-form');
  form.dataset.editId = entry.id;
  
  // Afficher la modale
  document.getElementById('add-password-overlay').classList.add('show');
  document.getElementById('add-password-modal').classList.add('show');
  
  // Activer le premier onglet
  document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
  document.querySelector('.tab-button[data-tab="password"]').classList.add('active');
  
  document.querySelectorAll('.tab-content').forEach(content => content.classList.add('hidden'));
  document.getElementById('password-tab').classList.remove('hidden');
}

// Ajouter la gestion de l'ajout de catégorie dans la modale
document.getElementById('btn-add-category-modal').addEventListener('click', () => {
  const newCategory = prompt('Nom de la nouvelle catégorie :');
  if (newCategory && newCategory.trim()) {
    categories.add(newCategory.trim());
    updateCategorySelect();
    document.getElementById('category-select').value = newCategory.trim();
    renderCategories();
    showNotification('Nouvelle catégorie ajoutée');
  }
});

// Gestion de l'overlay
document.getElementById('add-password-overlay').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) {
    e.target.classList.remove('show');
    document.getElementById('add-password-modal').classList.remove('show');
    document.getElementById('add-category-modal').classList.remove('show');
    document.getElementById('password-form').reset();
    document.getElementById('new-category-input').value = '';
  }
});

// Version finale de updateCategorySelect()
function updateCategorySelect() {
  const select = document.getElementById('category-select');
  const currentValue = select.value;
  
  // Vider le select
  select.innerHTML = '';
  
  // Ajouter l'option par défaut
  const defaultOption = document.createElement('option');
  defaultOption.value = '';
  defaultOption.textContent = 'Toutes les entrées';
  select.appendChild(defaultOption);
  
  // Ajouter toutes les catégories
  Array.from(categories).sort().forEach(category => {
    const option = document.createElement('option');
    option.value = category;
    option.textContent = category;
    select.appendChild(option);
  });
  
  // Restaurer la valeur sélectionnée si elle existe toujours
  if (currentValue && categories.has(currentValue)) {
    select.value = currentValue;
  }
}

// Fonctions pour le générateur de mots de passe
function generatePassword() {
  const length = document.getElementById('password-length').value;
  const useUppercase = document.getElementById('include-uppercase').checked;
  const useNumbers = document.getElementById('include-numbers').checked;
  const useSymbols = document.getElementById('include-symbols').checked;

  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const numbers = '0123456789';
  const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

  let chars = lowercase;
  if (useUppercase) chars += uppercase;
  if (useNumbers) chars += numbers;
  if (useSymbols) chars += symbols;

  let password = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * chars.length);
    password += chars[randomIndex];
  }

  return password;
}

function updatePasswordStrength(password) {
  const strengthBar = document.querySelector('.password-strength-bar');
  
  // Critères de force
  const hasLength = password.length >= 12;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSymbol = /[^A-Za-z0-9]/.test(password);
  
  const strength = [hasLength, hasUpper, hasLower, hasNumber, hasSymbol]
    .filter(Boolean).length;

  // Mise à jour visuelle
  strengthBar.className = 'password-strength-bar';
  if (strength <= 2) strengthBar.classList.add('strength-weak');
  else if (strength <= 4) strengthBar.classList.add('strength-medium');
  else strengthBar.classList.add('strength-strong');
}

document.getElementById('btn-generate-password').addEventListener('click', () => {
  const password = generatePassword();
  document.getElementById('password-input').value = password;
  updatePasswordStrength(password);
});

document.getElementById('password-length').addEventListener('input', (e) => {
  document.getElementById('password-length-value').textContent = 
    `${e.target.value} caractères`;
});

document.getElementById('btn-toggle-password').addEventListener('click', (e) => {
  const input = document.getElementById('password-input');
  const icon = e.currentTarget.querySelector('i');
  
  if (input.type === 'password') {
    input.type = 'text';
    icon.className = 'fas fa-eye-slash';
  } else {
    input.type = 'password';
    icon.className = 'fas fa-eye';
  }
});

document.getElementById('password-input').addEventListener('input', (e) => {
  updatePasswordStrength(e.target.value);
});

// La nouvelle fonction d'évaluation du MP (version finale)
function evaluateMasterPassword(password) {
  // Critères de validation
  const criteria = {
    length: password.length >= 12,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number: /[0-9]/.test(password),
    symbol: /[^A-Za-z0-9]/.test(password)
  };

  // Calcul du score (0-100)
  let score = 0;
  
  // Points de base pour la longueur
  if (password.length >= 8) score += 10;
  if (password.length >= 12) score += 10;
  if (password.length >= 16) score += 10;
  
  // Points pour chaque type de caractère
  if (criteria.uppercase) score += 20;
  if (criteria.lowercase) score += 20;
  if (criteria.number) score += 20;
  if (criteria.symbol) score += 20;

  // Limiter le score à 100
  score = Math.min(score, 100);

  // Déterminer le niveau
  let level, color;
  if (score < 20) {
    level = "Très faible";
    color = "#dc3545";
  } else if (score < 40) {
    level = "Faible";
    color = "#ffc107";
  } else if (score < 60) {
    level = "Moyen";
    color = "#ffc107";
  } else if (score < 80) {
    level = "Fort";
    color = "#28a745";
  } else {
    level = "Très fort";
    color = "#28a745";
  }

  // Mise à jour visuelle
  const strengthBar = document.querySelector('.master-password-input .password-strength-bar');
  const strengthText = document.querySelector('.master-password-input .password-strength-text');
  
  // Mettre à jour la barre de progression
  strengthBar.style.width = `${score}%`;
  strengthBar.style.backgroundColor = color;
  strengthText.textContent = level;
  strengthText.style.color = color;

  // Liste des critères manquants
  const criteriaList = document.querySelector('.password-criteria-list');
  if (criteriaList) {
    criteriaList.innerHTML = `
      <li class="${criteria.length ? 'valid' : ''}">
        <i class="fas ${criteria.length ? 'fa-check' : 'fa-times'}"></i>
        Au moins 12 caractères
      </li>
      <li class="${criteria.uppercase ? 'valid' : ''}">
        <i class="fas ${criteria.uppercase ? 'fa-check' : 'fa-times'}"></i>
        Au moins une majuscule
      </li>
      <li class="${criteria.lowercase ? 'valid' : ''}">
        <i class="fas ${criteria.lowercase ? 'fa-check' : 'fa-times'}"></i>
        Au moins une minuscule
      </li>
      <li class="${criteria.number ? 'valid' : ''}">
        <i class="fas ${criteria.number ? 'fa-check' : 'fa-times'}"></i>
        Au moins un chiffre
      </li>
      <li class="${criteria.symbol ? 'valid' : ''}">
        <i class="fas ${criteria.symbol ? 'fa-check' : 'fa-times'}"></i>
        Au moins un caractère spécial
      </li>
    `;
  }

  // On retourne toujours true pour permettre la création
  return true;
}

// Event sur le MP new
document.getElementById('master-password-new').addEventListener('input', (e) => {
  evaluateMasterPassword(e.target.value);
  document.getElementById('btn-create-session').disabled = false;
});

// Générer un code de version
function generateVersionCode() {
  const date = new Date();
  const year = date.getFullYear().toString().slice(-2);
  const month = (date.getMonth() + 1).toString().padStart(2, '0');
  const day = date.getDate().toString().padStart(2, '0');
  return `${year}${month}${day}-01`;
}

// Vérification HaveIBeenPwned
async function checkPasswordPwned(password) {
  try {
    // Générer le hash SHA-1 du mot de passe
    const sha1 = new jsSHA("SHA-1", "TEXT");
    sha1.update(password);
    const hash = sha1.getHash("HEX").toUpperCase();
    
    // On ne prend que les 5 premiers caractères pour l'API
    const prefix = hash.substring(0, 5);
    const suffix = hash.substring(5);
    
    // Appeler l'API HaveIBeenPwned avec k-anonymity
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: {
        'User-Agent': 'PasswordManager/1.0',
        'Accept': 'text/plain'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Erreur API: ${response.status}`);
    }
    
    const data = await response.text();
    
    // Chercher notre hash dans les résultats
    const hashes = data.split('\n');
    for (const h of hashes) {
      const [hashSuffix, count] = h.split(':');
      if (hashSuffix.trim().toUpperCase() === suffix) {
        return parseInt(count);
      }
    }
    
    return 0;
  } catch (error) {
    console.error('Erreur lors de la vérification HaveIBeenPwned:', error);
    return -1;
  }
}

// Version finale de analyzeVault (avec pwnedPasswords, etc.)
async function analyzeVault() {
  const analysis = {
    totalPasswords: currentData.length,
    categories: {
      total: new Set(currentData.map(entry => entry.category)).size,
      uncategorized: currentData.filter(e => !e.category).length
    },
    passwordStrength: {
      weak: 0,
      medium: 0,
      strong: 0
    },
    reusedPasswords: new Map(),
    similarPasswords: [],
    averageLength: 0,
    commonServices: new Map(),
    vulnerabilities: {
      tooShort: [],
      noSpecialChars: [],
      noNumbers: [],
      noUppercase: [],
      sequential: [],
      commonWords: []
    },
    recommendations: [],
    securityTips: [],
    pwnedPasswords: []
  };

  // Créer un Set pour éviter de vérifier plusieurs fois le même mot de passe
  const uniquePasswords = new Set(currentData.map(entry => entry.password));
  
  // Vérifier chaque mot de passe unique avec HaveIBeenPwned
  const pwnedChecks = await Promise.all(
    Array.from(uniquePasswords).map(async password => {
      const count = await checkPasswordPwned(password);
      if (count > 0) {
        // Trouver tous les services qui utilisent ce mot de passe
        const services = currentData
          .filter(entry => entry.password === password)
          .map(entry => entry.service);
          
        return {
          services,
          count,
          password: password.substring(0, 3) + '...' // Ne montrer que le début du MP
        };
      }
      return null;
    })
  );
  
  // Filtrer les résultats non-null
  analysis.pwnedPasswords = pwnedChecks.filter(result => result !== null);

  if (analysis.pwnedPasswords.length > 0) {
    analysis.recommendations.unshift({
      priority: 'high',
      icon: 'fa-exclamation-triangle',
      text: `${analysis.pwnedPasswords.length} mot(s) de passe compromis trouvé(s)`,
      details: analysis.pwnedPasswords.map(pwned => 
        `Le mot de passe utilisé pour ${pwned.services.join(', ')} a été trouvé ${pwned.count.toLocaleString()} fois dans des fuites de données.`
      ).join('\n')
    });

    analysis.securityTips.unshift({
      icon: 'fa-shield-alt',
      tip: 'Changez immédiatement vos mots de passe compromis',
      detail: 'Ces mots de passe ont été exposés dans des fuites de données et devraient être changés immédiatement.'
    });
  }

  // Analyser chaque entrée
  currentData.forEach(entry => {
    // Force du mot de passe
    const strength = evaluatePasswordStrength(entry.password);
    analysis.passwordStrength[strength]++;

    // Mots de passe réutilisés
    const reusedServices = analysis.reusedPasswords.get(entry.password) || [];
    reusedServices.push(entry.service);
    analysis.reusedPasswords.set(entry.password, reusedServices);

    // Longueur moyenne
    analysis.averageLength += entry.password.length;

    // Vulnérabilités
    if (entry.password.length < 12) {
      analysis.vulnerabilities.tooShort.push(entry.service);
    }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(entry.password)) {
      analysis.vulnerabilities.noSpecialChars.push(entry.service);
    }
    if (!/[0-9]/.test(entry.password)) {
      analysis.vulnerabilities.noNumbers.push(entry.service);
    }
    if (!/[A-Z]/.test(entry.password)) {
      analysis.vulnerabilities.noUppercase.push(entry.service);
    }
    if (/123|abc|qwerty|password|azerty/i.test(entry.password)) {
      analysis.vulnerabilities.sequential.push(entry.service);
    }
  });

  // Finaliser la moyenne
  if (currentData.length > 0) {
  analysis.averageLength = Math.round(analysis.averageLength / currentData.length);
  }

  // Mots de passe réellement réutilisés
  analysis.reusedPasswords.forEach((services, password) => {
    if (services.length > 1) {
      analysis.similarPasswords.push({
        services: services,
        count: services.length
      });
    }
  });

  // Recommandations
  if (analysis.vulnerabilities.tooShort.length > 0) {
    analysis.recommendations.push({
      priority: 'high',
      icon: 'fa-exclamation-triangle',
      text: `${analysis.vulnerabilities.tooShort.length} mots de passe sont trop courts (< 12 caractères)`,
      details: `Services concernés : ${analysis.vulnerabilities.tooShort.join(', ')}`
    });
  }
  if (analysis.similarPasswords.length > 0) {
    analysis.recommendations.push({
      priority: 'high',
      icon: 'fa-copy',
      text: `${analysis.similarPasswords.length} groupes de mots de passe sont réutilisés`,
      details: analysis.similarPasswords.map(group => 
        `Même mot de passe pour : ${group.services.join(', ')}`
      ).join('\n')
    });
  }
  if (analysis.vulnerabilities.noSpecialChars.length > 0) {
    analysis.recommendations.push({
      priority: 'medium',
      icon: 'fa-exclamation-circle',
      text: `${analysis.vulnerabilities.noSpecialChars.length} mots de passe sans caractères spéciaux`,
      details: `Services concernés : ${analysis.vulnerabilities.noSpecialChars.join(', ')}`
    });
  }
  if (analysis.categories.uncategorized > 0) {
    analysis.recommendations.push({
      priority: 'low',
      icon: 'fa-tags',
      text: `${analysis.categories.uncategorized} entrées ne sont pas catégorisées`,
      details: 'La catégorisation aide à mieux organiser vos mots de passe'
    });
  }

  // Conseils de sécurité
  if (analysis.vulnerabilities.tooShort.length > 0) {
    analysis.securityTips.push({
      icon: 'fa-ruler',
      tip: 'Augmentez la longueur de vos mots de passe',
      detail: 'Un mot de passe long est plus difficile à craquer. Utilisez des phrases complètes ou des suites de mots.'
    });
  }
  if (analysis.similarPasswords.length > 0) {
    analysis.securityTips.push({
      icon: 'fa-fingerprint',
      tip: 'Évitez la réutilisation des mots de passe',
      detail: 'Utilisez un mot de passe unique pour chaque service. En cas de fuite, un seul compte sera compromis.'
    });
  }
  if (
    analysis.vulnerabilities.noSpecialChars.length > 0 ||
      analysis.vulnerabilities.noNumbers.length > 0 || 
    analysis.vulnerabilities.noUppercase.length > 0
  ) {
    analysis.securityTips.push({
      icon: 'fa-random',
      tip: 'Diversifiez les types de caractères',
      detail: 'Combinez majuscules, chiffres et caractères spéciaux pour renforcer vos mots de passe.'
    });
  }
  if (analysis.vulnerabilities.sequential.length > 0) {
    analysis.securityTips.push({
      icon: 'fa-ban',
      tip: 'Évitez les séquences évidentes',
      detail: 'Les suites comme "123456" ou "azerty" sont les premières testées lors d\'une attaque.'
    });
  }
  if (analysis.securityTips.length < 2) {
    analysis.securityTips.push({
      icon: 'fa-shield-alt',
      tip: 'Activez l\'authentification à deux facteurs',
      detail: 'Quand c\'est possible, activez la 2FA pour une sécurité supplémentaire.'
    });
    analysis.securityTips.push({
      icon: 'fa-sync',
      tip: 'Changez régulièrement vos mots de passe',
      detail: 'Particulièrement pour les services critiques (banque, email...).'
    });
  }

  return analysis;
}

// Version finale de showAnalysis
async function showAnalysis() {
  analyzeModal.classList.add("show");
  analyzeOverlay.classList.add("show");
  analyzeLoading.classList.remove("hidden");
  analyzeResults.innerHTML = "";

  // Petit délai visuel
  await new Promise(resolve => setTimeout(resolve, 800));
  
  const analysis = await analyzeVault(); 
  
  analyzeLoading.classList.add("hidden");
  
  let pwnedSection = '';
  if (analysis.pwnedPasswords.length > 0) {
    pwnedSection = `
      <div class="analyze-section">
        <h4><i class="fas fa-skull-crossbones"></i> Mots de passe compromis</h4>
        ${analysis.pwnedPasswords.map(pwned => `
          <div class="analyze-metric danger">
            <i class="fas fa-exclamation-triangle"></i>
            <div class="pwned-content">
              <strong>Services affectés : ${pwned.services.join(', ')}</strong>
              <div class="pwned-details">
                Trouvé ${pwned.count.toLocaleString()} fois dans des fuites de données
              </div>
            </div>
          </div>
        `).join('')}
      </div>
    `;
  }

  analyzeResults.innerHTML = `
    <div class="analyze-section">
      <h4><i class="fas fa-chart-pie"></i> Vue d'ensemble</h4>
      <div class="analyze-metric">
        <i class="fas fa-key"></i>
        <span>${analysis.totalPasswords} mots de passe au total</span>
      </div>
      <div class="analyze-metric">
        <i class="fas fa-ruler"></i>
        <span>Longueur moyenne : ${analysis.averageLength} caractères</span>
      </div>
      <div class="analyze-metric ${analysis.passwordStrength.weak > 0 ? 'warning' : 'success'}">
        <i class="fas fa-shield-alt"></i>
        <span>
          <strong>${analysis.passwordStrength.strong}</strong> forts, 
          <strong>${analysis.passwordStrength.medium}</strong> moyens, 
          <strong>${analysis.passwordStrength.weak}</strong> faibles
        </span>
      </div>
    </div>

    ${pwnedSection}

    <div class="analyze-section">
      <h4><i class="fas fa-exclamation-triangle"></i> Points d'attention</h4>
      ${analysis.recommendations.map(rec => `
        <div class="analyze-metric ${rec.priority}">
          <i class="fas ${rec.icon}"></i>
          <div class="recommendation-content">
            <strong>${rec.text}</strong>
            ${rec.details ? `<div class="recommendation-details">${rec.details}</div>` : ''}
          </div>
        </div>
      `).join('')}
    </div>

    <div class="analyze-section">
      <h4><i class="fas fa-lightbulb"></i> Conseils personnalisés</h4>
      ${analysis.securityTips.map(tip => `
        <div class="analyze-metric info">
          <i class="fas ${tip.icon}"></i>
          <div class="security-tip-content">
            <strong>${tip.tip}</strong>
            <div class="tip-detail">${tip.detail}</div>
          </div>
        </div>
      `).join('')}
    </div>
  `;

  // Styles spécifiques
  const style = document.createElement('style');
  style.textContent += `
    .pwned-content {
      flex: 1;
    }
    .pwned-details {
      font-size: 0.9em;
      color: #721c24;
      margin-top: 5px;
    }
    .analyze-metric.danger {
      background: #f8d7da;
      border-left: 4px solid #dc3545;
    }
    .analyze-metric.danger i {
      color: #dc3545;
    }
  `;
  document.head.appendChild(style);
}

// Écouteurs analyse
btnAnalyze.addEventListener("click", showAnalysis);
btnCloseAnalyze.addEventListener("click", () => {
  analyzeModal.classList.remove("show");
  analyzeOverlay.classList.remove("show");
});

// OTP
function generateTOTP(secret, time = Date.now()) {
  const period = Math.floor(time / 30000);
  const counter = new ArrayBuffer(8);
  const view = new DataView(counter);
  view.setBigUint64(0, BigInt(period));
  
  const key = base32ToBuffer(secret.toUpperCase());
  
  const hmac = new jsSHA("SHA-1", "ARRAYBUFFER");
  hmac.setHMACKey(key, "ARRAYBUFFER");
  hmac.update(counter);
  const hash = hmac.getHMAC("ARRAYBUFFER");
  
  const offset = new Uint8Array(hash)[19] & 0xf;
  
  const view2 = new DataView(hash);
  const code = view2.getUint32(offset) & 0x7fffffff;
  
  return ("000000" + (code % 1000000)).slice(-6);
}

function base32ToBuffer(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = new Uint8Array(Math.ceil(base32.length * 5 / 8));
  let index = 0;

  for (let i = 0; i < base32.length; i++) {
    value = (value << 5) | alphabet.indexOf(base32[i]);
    bits += 5;
    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }

  return output.buffer;
}

function updateOTPDisplay() {
  const now = Date.now();
  const timeStep = 30000;
  const timeLeft = timeStep - (now % timeStep);
  const progress = (timeLeft / timeStep) * 100;

  const otpDisplays = document.querySelectorAll('.otp-display');
  otpDisplays.forEach(display => {
    const secret = display.dataset.secret;
    if (secret) {
      const code = generateTOTP(secret);
      display.textContent = code;
      
      const timer = display.closest('.field-header').querySelector('.otp-timer');
      if (timer) {
        timer.style.setProperty('--progress', `${progress}%`);
      }
    }
  });

  setTimeout(() => {
    updateOTPDisplay();
  }, 1000);
}
updateOTPDisplay();

document.querySelectorAll('.tab-button').forEach(button => {
  button.addEventListener('click', () => {
    document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
    button.classList.add('active');
    
    document.querySelectorAll('.tab-content').forEach(content => {
      content.classList.add('hidden');
    });
    
    const tabId = button.dataset.tab;
    document.getElementById(`${tabId}-tab`).classList.remove('hidden');
  });
});

// Vérification OTP
document.getElementById('btn-verify-otp').addEventListener('click', () => {
  const secretInput = document.getElementById('otp-secret');
  const secret = secretInput.value.trim().toUpperCase();
  
  if (!/^[A-Z2-7]+=*$/.test(secret)) {
    showNotification('Clé secrète invalide', true);
    return;
  }
  
  try {
    const code = generateTOTP(secret);
    const previewContainer = document.querySelector('.otp-preview');
    previewContainer.innerHTML = `
      <div class="otp-preview-header">
        <span class="otp-display" data-secret="${secret}">${code}</span>
        <button class="btn-copy-otp" title="Copier le code">
          <i class="fas fa-copy"></i>
        </button>
      </div>
      <div class="otp-timer"></div>
    `;

    previewContainer.querySelector('.btn-copy-otp').addEventListener('click', () => {
      navigator.clipboard.writeText(code)
        .then(() => showNotification('Code 2FA copié !'))
        .catch(() => showNotification('Échec de la copie', true));
    });
    
    document.getElementById('password-form').dataset.otpSecret = secret;
    
    showNotification('Code OTP vérifié avec succès');
  } catch (error) {
    showNotification('Erreur lors de la vérification de la clé', true);
  }
});

function applyPasswordItemStyles(passwordItem, entry) {
  if (entry.category) {
    const categoryColor = getCategoryColor(entry.category);
    if (categoryColor) {
      passwordItem.style.setProperty('--category-color', categoryColor);
    }
  }
  if (entry.favorite) {
    passwordItem.classList.add('favorite');
  }
  if (entry.otp) {
    passwordItem.classList.add('has-otp');
  }
}

// Gestion de la version
function incrementVaultVersion() {
  if (currentVaultVersion) {
    const [datePart, versionNumber] = currentVaultVersion.split('-');
    const newVersionNumber = (parseInt(versionNumber) + 1).toString().padStart(2, '0');
    currentVaultVersion = `${datePart}-${newVersionNumber}`;
  } else {
    currentVaultVersion = generateVersionCode();
  }
  updateDataSection();
  autoSave();
}

// Auto-lock
function initAutoLock() {
  const autoLockEnabled = document.getElementById('auto-lock').checked;
  const lockTimeout = parseInt(document.getElementById('lock-timeout').value) * 60 * 1000;

  if (autoLockTimeout) {
    clearInterval(autoLockTimeout);
  }

  if (autoLockEnabled) {
    autoLockTimeout = setInterval(() => {
      const inactiveTime = Date.now() - lastActivityTime;
      if (inactiveTime >= lockTimeout && !isLocked) {
        lockVault();
      }
    }, 1000);
  }
}

// Modifier la fonction lockVault pour ajouter le bouton de retour
function lockVault() {
  // Sauvegarder la session avant de verrouiller
  saveSession().then(() => {
    // Effacer les données sensibles de la mémoire
    masterKey = null;
    masterPassword = "";
    
    // Afficher l'écran de verrouillage
    const lockOverlay = document.createElement('div');
    lockOverlay.id = 'lock-overlay';
    lockOverlay.innerHTML = `
      <div class="lock-content">
        <div class="lock-icon">
          <i class="fas fa-lock"></i>
        </div>
        <h2>Vault verrouillé</h2>
        <p>Entrez votre mot de passe maître pour déverrouiller</p>
        <div class="master-password-input">
          <input type="password" id="unlock-password" placeholder="Mot de passe maître" />
        </div>
        <div class="lock-buttons">
          <button id="btn-unlock" class="btn-action">
            <i class="fas fa-unlock"></i> Déverrouiller
          </button>
          <button id="btn-back-home" class="btn-action btn-secondary">
            <i class="fas fa-home"></i> Retour à l'accueil
          </button>
        </div>
        <p id="unlock-error" class="error-message"></p>
      </div>
    `;
    
    document.body.appendChild(lockOverlay);
    document.getElementById('unlock-password').focus();
    
    // Gérer le déverrouillage
    const unlockBtn = document.getElementById('btn-unlock');
    const unlockInput = document.getElementById('unlock-password');
    const backHomeBtn = document.getElementById('btn-back-home');
    
    const handleUnlock = async () => {
      const password = unlockInput.value;
      const success = await restoreSession(password);
      
      if (success) {
        lockOverlay.remove();
        showNotification('Vault déverrouillé');
        renderCategories();
        renderPasswords();
        updateDataSection();
      } else {
        document.getElementById('unlock-error').textContent = 'Mot de passe incorrect';
        unlockInput.value = '';
      }
    };
    
    unlockBtn.addEventListener('click', handleUnlock);
    unlockInput.addEventListener('keyup', (e) => {
      if (e.key === 'Enter') handleUnlock();
    });

    // Gérer le retour à l'accueil
    backHomeBtn.addEventListener('click', () => {
      if (confirm('Êtes-vous sûr de vouloir retourner à l\'accueil ? Les données seront effacées de la mémoire.')) {
        // Effacer le localStorage
        Object.values(STORAGE_KEYS).forEach(key => localStorage.removeItem(key));
        
        // Effacer les variables en mémoire
        masterKey = null;
        masterPassword = "";
        currentData = [];
        currentFileImported = false;
        currentCategory = null;
        currentSalt = null;
        categories = new Set();
        categoryColors = new Map();
        
        // Retourner à l'écran d'accueil
        lockOverlay.remove();
        welcomeScreen.classList.remove("hidden");
        appScreen.classList.add("hidden");
        
        showNotification('Vault fermé et données effacées');
      }
    });
  });
}

function unlockVault() {
  isLocked = false;
  lastActivityTime = Date.now();
  const lockOverlay = document.getElementById('lock-overlay');
  if (lockOverlay) {
    lockOverlay.remove();
  }
}

function resetActivityTimer() {
  lastActivityTime = Date.now();
}
document.addEventListener('mousemove', resetActivityTimer);
document.addEventListener('keydown', resetActivityTimer);
document.addEventListener('click', resetActivityTimer);
document.addEventListener('scroll', resetActivityTimer);

// Appliquer les paramètres
function applySettings() {
  const savedTheme = localStorage.getItem('theme') || currentSettings.theme || 'light';
  
  document.getElementById('language-select').value = currentSettings.language;
  document.getElementById('theme-select').value = savedTheme;
  document.documentElement.setAttribute('data-theme', savedTheme);
  currentSettings.theme = savedTheme;

  document.getElementById('auto-lock').checked = currentSettings.autoLock;
  document.getElementById('lock-timeout').value = currentSettings.lockTimeout;
  document.getElementById('double-auth').checked = currentSettings.doubleAuth;

  if (currentSettings.autoLock) {
    initAutoLock();
  }
}

// Raccourcis
document.getElementById('btn-search').addEventListener('click', toggleSearchBar);
document.getElementById('btn-close-search').addEventListener('click', toggleSearchBar);
document.getElementById('btn-sort-view').addEventListener('click', toggleView);

function toggleSearchBar() {
  const searchBar = document.getElementById('search-bar');
  searchBar.classList.toggle('hidden');
  if (!searchBar.classList.contains('hidden')) {
    document.getElementById('search-input').focus();
  }
}

function toggleView() {
  isGridView = !isGridView;
  const btn = document.getElementById('btn-sort-view');
  const icon = btn.querySelector('i');
  const text = btn.querySelector('span');
  
  if (isGridView) {
    icon.className = 'fas fa-list';
    text.textContent = 'Vue liste';
    document.querySelector('.password-list').classList.add('grid-view');
  } else {
    icon.className = 'fas fa-th-large';
    text.textContent = 'Vue grille';
    document.querySelector('.password-list').classList.remove('grid-view');
  }
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    const passwordOverlay = document.getElementById('add-password-overlay');
    const passwordModal = document.getElementById('add-password-modal');
    
    if (passwordOverlay.classList.contains('show')) {
      passwordOverlay.classList.remove('show');
      passwordModal.classList.remove('show');
  document.getElementById('password-form').reset();
      return;
    }
    
    const settingsOverlay = document.getElementById('settings-overlay');
    const settingsModal = document.getElementById('settings-modal');
    if (settingsOverlay.classList.contains('show')) {
      settingsOverlay.classList.remove('show');
      settingsModal.classList.remove('show');
      return;
    }
    
    const searchBar = document.getElementById('search-bar');
    if (!searchBar.classList.contains('hidden')) {
      toggleSearchBar();
      return;
    }

    const analyzeOverlay = document.getElementById('analyze-overlay');
    const analyzeModal = document.getElementById('analyze-modal');
    if (analyzeOverlay.classList.contains('show')) {
      analyzeOverlay.classList.remove('show');
      analyzeModal.classList.remove('show');
      return;
    }
  }

  const isModalOpen = [
    'add-password-overlay',
    'settings-overlay',
    'analyze-overlay'
  ].some(id => document.getElementById(id).classList.contains('show'));

  if (isModalOpen) return;

  const isInputActive = document.activeElement.tagName === 'INPUT' || 
                       document.activeElement.tagName === 'TEXTAREA';
  if (isInputActive) return;

  if (e.key.toLowerCase() === 'n' && e.altKey && !e.ctrlKey && !e.shiftKey) {
    e.preventDefault();
    document.getElementById('btn-add-password').click();
  }

  if (e.key.toLowerCase() === 'e' && e.altKey && !e.ctrlKey && !e.shiftKey) {
    e.preventDefault();
    document.getElementById('btn-export').click();
  }
});

document.getElementById('btn-docs').addEventListener('click', () => {
  window.open('doc.html', '_blank');
});

// Paramètres
document.getElementById('btn-settings').addEventListener('click', () => {
  document.getElementById('settings-overlay').classList.add('show');
  document.getElementById('settings-modal').classList.add('show');
});

document.getElementById('btn-cancel-settings').addEventListener('click', () => {
  document.getElementById('settings-overlay').classList.remove('show');
  document.getElementById('settings-modal').classList.remove('show');
});

document.getElementById('settings-form').addEventListener('submit', (e) => {
  e.preventDefault();
  
  currentSettings = {
    language: document.getElementById('language-select').value,
    theme: document.getElementById('theme-select').value,
    autoLock: document.getElementById('auto-lock').checked,
    lockTimeout: parseInt(document.getElementById('lock-timeout').value),
    doubleAuth: document.getElementById('double-auth').checked
  };
  
  // Sauvegarder le thème dans le localStorage
  localStorage.setItem('theme', currentSettings.theme);
  
  applySettings();
  
  document.getElementById('settings-overlay').classList.remove('show');
  document.getElementById('settings-modal').classList.remove('show');
  
  showNotification('Paramètres enregistrés');
  incrementVaultVersion();
});

// =====================
// Statistiques & DataSection
// =====================
function updateDataSection() {
  const dataSection = document.querySelector('.data-section');
  const isOutdated = currentVaultVersion !== savedVaultVersion;

  let displayVersion = 'N/A';
  if (currentVaultVersion) {
    const [datePart, versionNumber] = currentVaultVersion.split('-');
    const year = '20' + datePart.slice(0, 2);
    const month = datePart.slice(2, 4);
    const day = datePart.slice(4, 6);
    displayVersion = `${day}/${month}/${year} (v${versionNumber})`;
  }

  dataSection.innerHTML = `
    <div class="stat-card">
      <div class="stat-icon">
        <i class="fas fa-key"></i>
      </div>
      <div class="stat-content">
        <div class="stat-value">${currentData.length}</div>
        <div class="stat-label">Mots de passe</div>
      </div>
    </div>

    <div class="stat-card">
      <div class="stat-icon">
        <i class="fas fa-code-branch"></i>
      </div>
      <div class="stat-content">
        <div class="stat-value">${displayVersion}</div>
        <div class="stat-label">Version du Vault</div>
      </div>
    </div>

    <div class="stat-card ${isOutdated ? 'warning' : 'success'}">
      <div class="stat-icon">
        <i class="fas ${isOutdated ? 'fa-exclamation-triangle' : 'fa-check-circle'}"></i>
      </div>
      <div class="stat-content">
        <div class="stat-value">${isOutdated ? 'Non exporté' : 'Sauvegardé'}</div>
        <div class="stat-label">État du Vault</div>
      </div>
    </div>
  `;
}

// =====================
// Catégories (couleurs, édition)
// =====================
let categoryColors = new Map();

function getCategoryColor(category) {
  return categoryColors.get(category);
}

function setCategoryColor(category, color) {
  categoryColors.set(category, color);
}

function updateCategoryName(oldName, newName) {
  currentData.forEach(entry => {
    if (entry.category === oldName) {
      entry.category = newName;
    }
  });
  
  const oldColor = categoryColors.get(oldName);
  if (oldColor) {
    categoryColors.delete(oldName);
    categoryColors.set(newName, oldColor);
  }
  
  if (currentCategory === oldName) {
    currentCategory = newName;
  }
  
  categories.delete(oldName);
  categories.add(newName);

  incrementVaultVersion();
}

function showCategoryEditModal(category) {
  const modal = document.createElement("div");
  modal.classList.add("modal", "category-edit-modal");
  
  const colorButtons = Object.entries(CATEGORY_COLORS)
    .map(([name, value]) => `
      <button type="button" 
              class="color-choice ${getCategoryColor(category) === value ? 'selected' : ''}"
              data-color="${value}"
              style="background-color: ${value}">
      </button>
    `).join('');

  modal.innerHTML = `
    <h3>Modifier la catégorie</h3>
    <form id="category-edit-form">
      <div class="form-group">
        <label for="category-name">Nom</label>
        <input type="text" id="category-name" value="${category}" required>
      </div>
      <div class="form-group">
        <label>Couleur</label>
        <div class="color-choices">
          ${colorButtons}
        </div>
      </div>
      <div class="modal-buttons">
        <button type="button" class="btn-action" id="btn-cancel-category-edit">Annuler</button>
        <button type="submit" class="btn-action">Enregistrer</button>
      </div>
    </form>
  `;

  const overlay = document.createElement("div");
  overlay.classList.add("modal-overlay");
  
  document.body.appendChild(overlay);
  document.body.appendChild(modal);
  
  overlay.classList.add("show");
  modal.classList.add("show");

  let selectedColor = getCategoryColor(category) || CATEGORY_COLORS.blue;
  modal.querySelectorAll('.color-choice').forEach(btn => {
    btn.addEventListener('click', () => {
      modal.querySelectorAll('.color-choice').forEach(b => b.classList.remove('selected'));
      btn.classList.add('selected');
      selectedColor = btn.dataset.color;
    });
  });

  const form = modal.querySelector("form");
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const newName = document.getElementById("category-name").value.trim();
    
    if (newName && newName !== category) {
      updateCategoryName(category, newName);
    }
    setCategoryColor(newName || category, selectedColor);
    
    closeModal();
    renderCategories();
    renderPasswords();
  });

  modal.querySelector("#btn-cancel-category-edit").addEventListener("click", closeModal);
  overlay.addEventListener("click", closeModal);

  function closeModal() {
    modal.remove();
    overlay.remove();
  }
}

// Constantes pour le stockage local
const STORAGE_KEYS = {
  VAULT: 'encrypted_vault',
  SALT: 'vault_salt',
  VERSION: 'vault_version',
  SETTINGS: 'vault_settings'
};

// Fonction pour sauvegarder la session de manière sécurisée
async function saveSession() {
  try {
    if (!masterKey || !currentData) {
      throw new Error("Données de session invalides");
    }

    // Créer l'objet de session
    const sessionData = {
      data: currentData,
      settings: currentSettings,
      categories: Array.from(categories),
      categoryColors: Object.fromEntries(categoryColors),
      version: currentVaultVersion
    };

    // Générer un nouveau vecteur d'initialisation
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // Convertir les données en string
    const sessionStr = JSON.stringify(sessionData);
    const encodedSession = new TextEncoder().encode(sessionStr);

    // Chiffrer les données
    const encryptedData = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      masterKey,
      encodedSession
    );

    // Sauvegarder dans le localStorage
    const sessionObject = {
      iv: arrayBufferToBase64(iv),
      data: arrayBufferToBase64(encryptedData),
      timestamp: new Date().toISOString()
    };

    localStorage.setItem(STORAGE_KEYS.VAULT, JSON.stringify(sessionObject));
    localStorage.setItem(STORAGE_KEYS.SALT, arrayBufferToBase64(currentSalt));
    localStorage.setItem(STORAGE_KEYS.VERSION, currentVaultVersion);
    
    // Sauvegarder les paramètres non sensibles séparément
    const publicSettings = {
      language: currentSettings.language,
      theme: currentSettings.theme
    };
    localStorage.setItem(STORAGE_KEYS.SETTINGS, JSON.stringify(publicSettings));

  } catch (error) {
    console.error('Erreur lors de la sauvegarde de la session:', error);
    showNotification('Erreur lors de la sauvegarde de la session', true);
  }
}

// Fonction pour restaurer la session
async function restoreSession(password) {
  try {
    // Vérifier si une session existe
    const encryptedSession = localStorage.getItem(STORAGE_KEYS.VAULT);
    const storedSalt = localStorage.getItem(STORAGE_KEYS.SALT);
    
    if (!encryptedSession || !storedSalt) {
      return false;
    }

    // Récupérer le salt et dériver la clé
    currentSalt = base64ToArrayBuffer(storedSalt);
    const key = await deriveKeyFromPassword(password, currentSalt);

    // Déchiffrer les données
    const sessionObject = JSON.parse(encryptedSession);
    const iv = base64ToArrayBuffer(sessionObject.iv);
    const encryptedData = base64ToArrayBuffer(sessionObject.data);

    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      encryptedData
    );

    // Parser les données déchiffrées
    const sessionStr = new TextDecoder().decode(decrypted);
    const sessionData = JSON.parse(sessionStr);

    // Restaurer l'état
    currentData = sessionData.data;
    currentSettings = { ...currentSettings, ...sessionData.settings };
    categories = new Set(sessionData.categories);
    categoryColors = new Map(Object.entries(sessionData.categoryColors));
    currentVaultVersion = sessionData.version;
    masterKey = key;
    masterPassword = password;

    // Restaurer les paramètres publics
    const publicSettings = JSON.parse(localStorage.getItem(STORAGE_KEYS.SETTINGS) || '{}');
    currentSettings = { ...currentSettings, ...publicSettings };
    
    // Afficher l'écran principal
    welcomeScreen.classList.add("hidden");
    appScreen.classList.remove("hidden");

    return true;
  } catch (error) {
    console.error('Erreur lors de la restauration de la session:', error);
    return false;
  }
}

// Fonction pour verrouiller le Vault
function lockVault() {
  // Sauvegarder la session avant de verrouiller
  saveSession().then(() => {
    // Effacer les données sensibles de la mémoire
    masterKey = null;
    masterPassword = "";
    
    // Afficher l'écran de verrouillage
    const lockOverlay = document.createElement('div');
    lockOverlay.id = 'lock-overlay';
    lockOverlay.innerHTML = `
      <div class="lock-content">
        <div class="lock-icon">
          <i class="fas fa-lock"></i>
        </div>
        <h2>Vault verrouillé</h2>
        <p>Entrez votre mot de passe maître pour déverrouiller</p>
        <div class="master-password-input">
          <input type="password" id="unlock-password" placeholder="Mot de passe maître" />
        </div>
        <div class="lock-buttons">
          <button id="btn-unlock" class="btn-action">
            <i class="fas fa-unlock"></i> Déverrouiller
          </button>
          <button id="btn-back-home" class="btn-action btn-secondary">
            <i class="fas fa-home"></i> Retour à l'accueil
          </button>
        </div>
        <p id="unlock-error" class="error-message"></p>
      </div>
    `;
    
    document.body.appendChild(lockOverlay);
    document.getElementById('unlock-password').focus();
    
    // Gérer le déverrouillage
    const unlockBtn = document.getElementById('btn-unlock');
    const unlockInput = document.getElementById('unlock-password');
    const backHomeBtn = document.getElementById('btn-back-home');
    
    const handleUnlock = async () => {
      const password = unlockInput.value;
      const success = await restoreSession(password);
      
      if (success) {
        lockOverlay.remove();
        showNotification('Vault déverrouillé');
        renderCategories();
        renderPasswords();
        updateDataSection();
      } else {
        document.getElementById('unlock-error').textContent = 'Mot de passe incorrect';
        unlockInput.value = '';
      }
    };
    
    unlockBtn.addEventListener('click', handleUnlock);
    unlockInput.addEventListener('keyup', (e) => {
      if (e.key === 'Enter') handleUnlock();
    });

    // Gérer le retour à l'accueil
    backHomeBtn.addEventListener('click', () => {
      if (confirm('Êtes-vous sûr de vouloir retourner à l\'accueil ? Les données seront effacées de la mémoire.')) {
        // Effacer le localStorage
        Object.values(STORAGE_KEYS).forEach(key => localStorage.removeItem(key));
        
        // Effacer les variables en mémoire
        masterKey = null;
        masterPassword = "";
        currentData = [];
        currentFileImported = false;
        currentCategory = null;
        currentSalt = null;
        categories = new Set();
        categoryColors = new Map();
        
        // Retourner à l'écran d'accueil
        lockOverlay.remove();
        welcomeScreen.classList.remove("hidden");
        appScreen.classList.add("hidden");
        
        showNotification('Vault fermé et données effacées');
      }
    });
  });
}

// Fonction pour fermer complètement le Vault
function closeVault() {
  if (confirm('Êtes-vous sûr de vouloir fermer le Vault ? Toutes les données seront effacées du navigateur.')) {
    // Effacer le localStorage
    Object.values(STORAGE_KEYS).forEach(key => localStorage.removeItem(key));
    
    // Effacer les variables en mémoire
    masterKey = null;
    masterPassword = "";
    currentData = [];
    currentFileImported = false;
    currentCategory = null;
    currentSalt = null;
    categories = new Set();
    categoryColors = new Map();
    
    // Retourner à l'écran d'accueil
    welcomeScreen.classList.remove("hidden");
    appScreen.classList.add("hidden");
    
    showNotification('Vault fermé et données effacées');
  }
}

// Ajouter les écouteurs d'événements
document.getElementById('btn-lock').addEventListener('click', lockVault);
document.getElementById('btn-close-vault').addEventListener('click', closeVault);

// Sauvegarder automatiquement après chaque modification
function autoSave() {
  if (masterKey) {
    saveSession();
  }
}

// Modifier les fonctions existantes pour inclure l'auto-save
const existingRenderPasswords = renderPasswords;
renderPasswords = function() {
  existingRenderPasswords();
  autoSave();
};

// Ajouter le raccourci clavier pour le verrouillage
document.addEventListener('keydown', (e) => {
  if (e.altKey && e.key.toLowerCase() === 'l' && !e.ctrlKey && !e.shiftKey) {
    e.preventDefault();
    lockVault();
  }
});

// Vérifier s'il y a une session à restaurer au chargement
document.addEventListener('DOMContentLoaded', async () => {
  // ... code existant ...
  
  // Vérifier s'il y a une session sauvegardée
  const hasSession = localStorage.getItem(STORAGE_KEYS.VAULT) !== null;
  
  if (hasSession) {
    // Afficher directement l'écran de déverrouillage
    lockVault();
  }
});

// Ajouter au début du fichier, avec les autres écouteurs DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
  // ... code existant ...
  
  // Appliquer le thème sauvegardé au chargement initial
  const savedTheme = localStorage.getItem('theme') || 'light';
  document.documentElement.setAttribute('data-theme', savedTheme);
  
  // Mettre à jour le sélecteur de thème
  const themeSelect = document.getElementById('theme-select');
  if (themeSelect) {
    themeSelect.value = savedTheme;
  }
  
  // Si on a des currentSettings, mettre à jour le thème
  if (currentSettings) {
    currentSettings.theme = savedTheme;
  }
});

// Ajouter un écouteur pour le select de thème pour appliquer immédiatement les changements
document.getElementById('theme-select').addEventListener('change', (e) => {
  const newTheme = e.target.value;
  localStorage.setItem('theme', newTheme);
  document.documentElement.setAttribute('data-theme', newTheme);
});

function evaluatePasswordStrength(password) {
  // Critères de validation
  const criteria = {
    length: password.length >= 12,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number: /[0-9]/.test(password),
    symbol: /[^A-Za-z0-9]/.test(password)
  };

  // Calcul du score
  let score = 0;
  if (criteria.length) score += 20;
  if (criteria.uppercase) score += 20;
  if (criteria.lowercase) score += 20;
  if (criteria.number) score += 20;
  if (criteria.symbol) score += 20;

  // Déterminer le niveau
  if (score < 40) return 'weak';
  if (score < 80) return 'medium';
  return 'strong';
}
