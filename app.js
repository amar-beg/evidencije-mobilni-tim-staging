// ===== COGNITO KONFIGURACIJA =====
const COGNITO_DOMAIN = 'us-east-1vfdixxwye.auth.us-east-1.amazoncognito.com';
const COGNITO_CLIENT_ID = 'emnukq3526cng4mbabp3vqak6'; // ← ISPRAVAN Client ID!

// ⚠️ SECURITY: Client Secret je UKLONJEN!
// Public client apps (frontend) NE SMIJU imati client secret!
// Client Secret je samo za backend servere koji mogu čuvati tajne.
const COGNITO_CLIENT_SECRET = null; // Public client - no secret needed

const REDIRECT_URI = 'https://d3og0hrm88210h.cloudfront.net/app.html';
const SCOPE = 'openid email profile aws.cognito.signin.user.admin';

// ===== n8n WEBHOOK URLs =====
const N8N_WEBHOOK_URL = 'https://amar.prodesign387.com/webhook/submit-session';
const N8N_HISTORY_URL = 'https://amar.prodesign387.com/webhook/get-sessions';
const N8N_UPDATE_URL = 'https://amar.prodesign387.com/webhook/update-session';
const N8N_DELETE_URL = 'https://amar.prodesign387.com/webhook/delete-session';

const REQUIRE_AUTH = true;

// ===== HISTORY CACHE =====
// Client-side cache za "Raniji unosi" - smanjuje latency i API calls
const CACHE_CONFIG = {
  enabled: true,
  duration: 5 * 60 * 1000, // 5 minuta
  storageKey: 'history_cache'
};

// In-memory cache object
let historyCache = {
  today: { data: null, timestamp: null },
  current_month: { data: null, timestamp: null },
  previous_month: { data: null, timestamp: null }
};

// ===== CACHE HELPER FUNCTIONS =====

// Učitaj cache iz localStorage pri page load-u
function loadCacheFromStorage() {
  if (!CACHE_CONFIG.enabled) return;
  
  try {
    const stored = localStorage.getItem(CACHE_CONFIG.storageKey);
    if (stored) {
      const parsed = JSON.parse(stored);
      
      // Provjeri da li je cache još fresh
      const now = Date.now();
      for (const filter in parsed) {
        const cached = parsed[filter];
        if (cached && cached.timestamp) {
          const age = now - cached.timestamp;
          if (age < CACHE_CONFIG.duration) {
            historyCache[filter] = cached;
            console.log(`📦 Loaded cache for "${filter}" from localStorage (age: ${Math.round(age/1000)}s)`);
          } else {
            console.log(`📦 Discarded stale cache for "${filter}" (age: ${Math.round(age/1000)}s)`);
          }
        }
      }
    }
  } catch (e) {
    console.warn('Failed to load cache from localStorage:', e);
  }
}

// 🚀 PROACTIVE CACHE REFRESH
// Osvježava cache u pozadini (nakon POST-a) bez blokiranja UI-a
async function refreshHistoryCacheInBackground() {
  if (!CACHE_CONFIG.enabled) return;
  
  console.log('📦 Background cache refresh starting...');
  
  // Osvježi sve 3 filtera paralelno
  const filters = ['today', 'current_month', 'previous_month'];
  
  const refreshPromises = filters.map(async (filter) => {
    try {
      const headers = {
        'Content-Type': 'application/json'
      };

      if (REQUIRE_AUTH && accessToken) {
        headers['Authorization'] = 'Bearer ' + accessToken;
      }

      const url = `${N8N_HISTORY_URL}?filter=${filter}`;
      const response = await fetch(url, {
        method: 'GET',
        headers: headers
      });

      if (!response.ok) {
        console.warn(`Failed to refresh cache for "${filter}":`, response.status);
        return;
      }

      const data = await response.json();
      let sessions = [];
      
      if (Array.isArray(data)) {
        sessions = data;
      } else if (data && Array.isArray(data.sessions)) {
        sessions = data.sessions;
      } else if (data && typeof data === 'object') {
        sessions = [data];
      }

      // Filtriraj prazne objekte
      sessions = sessions.filter(session => {
        return session.activityDate || session.school || session.timestamp;
      });

      // Update cache
      historyCache[filter] = {
        data: sessions,
        timestamp: Date.now()
      };
      
      console.log(`📦 Cache refreshed for "${filter}" (${sessions.length} items)`);
      
    } catch (error) {
      console.warn(`Failed to refresh cache for "${filter}":`, error.message);
    }
  });
  
  // Sačekaj sve refresh-e
  await Promise.all(refreshPromises);
  
  // Persist to localStorage
  try {
    localStorage.setItem(CACHE_CONFIG.storageKey, JSON.stringify(historyCache));
    console.log('📦 Cache persisted to localStorage');
  } catch (e) {
    console.warn('Failed to persist cache:', e);
  }
  
  console.log('📦 Background cache refresh complete!');
}

// ===== GLOBALNI USER PODACI (iz ID tokena) =====
let currentUser = {
  firstName: '',
  lastName: '',
  email: '',
  position: '',
  homeSchool: '',
  role: ''
};

// ===== PKCE HELPER FUNKCIJE =====
function b64url(arr) {
  return btoa(String.fromCharCode(...arr))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function randomBytes(n = 64) {
  const arr = new Uint8Array(n);
  crypto.getRandomValues(arr);
  return arr;
}

async function sha256(buffer) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buffer));
}

// TODO: Izmijeni liste škola, kategorija, tipova rada i članova tima
const SCHOOLS = [
  'JU "Četvrta osnovna škola"',
  'JU "Deseta osnovna škola"',
  'JU "Deveta osnovna škola"',
  'JU "Druga osnovna škola"',
  'JU "Peta osnovna škola"',
  'JU "Prva osnovna škola" Ilidža',
  'JU "Sedma osnovna škola" Ilidža',
  'JU "Šesta osnovna škola"',
  'JU "Treća osnovna škola"',
  'JU "9. maj" Pazarić',
  'JU Centar za odgoj, obrazovanje i rehabilitaciju "Vladimir Nazor"',
  'JU Centar za slušnu i govornu rehabilitaciju, Sarajevo',
  'JU Centar za slijepu i slabovidnu djecu i omladinu, Sarajevo',
  'JU Osma osnovna škola "Amer Ćenanović" Ilidža',
  'JU Osnovna muzička i baletska škola "Novo Sarajevo"',
  'JU Osnovna muzička škola "Mladen Pozajić"',
  'JU Osnovna muzička škola Ilidža',
  'JU Srednja medicinska škola - Jezero Sarajevo',
  'JU Srednja škola primijenjenih umjetnosti',
  'JU Zavod za specijalno obrazovanje i odgoj djece "Mjedenica"',
  'JU OŠ "6. mart"',
  'JU OŠ "Aleksa Šantić"',
  'JU OŠ "Alija Nametak"',
  'JU OŠ "Aneks"',
  'JU OŠ "Avdo Smajlović"',
  'JU OŠ "Behaudin Selmanović"',
  'JU OŠ "Čamil Sijarić"',
  'JU OŠ "Čengić Vila I"',
  'JU OŠ "Džemaludin Čaušević"',
  'JU OŠ "Edhem Mulabdić"',
  'JU OŠ "Fatima Gunić"',
  'JU OŠ "Grbavica I"',
  'JU OŠ "Grbavica II"',
  'JU OŠ "Hamdija Kreševljaković"',
  'JU OŠ "Hasan Kaimija"',
  'JU OŠ "Hasan Kikić"',
  'JU OŠ "Hašim Spahić"',
  'JU OŠ "Hilmi ef. Šarić" Tarčin',
  'JU OŠ "Hrasno"',
  'JU OŠ "Isak Samokovlija"',
  'JU OŠ "Izet Šabić"',
  'JU OŠ "Kovačići"',
  'JU OŠ "Malta"',
  'JU OŠ "Mehmed-beg Kapetanović Ljubušak"',
  'JU OŠ "Mehmedalija Mak Dizdar"',
  'JU OŠ "Meša Selimović"',
  'JU OŠ "Mirsad Prnjavorac"',
  'JU OŠ "Mula Mustafa Bašeskija"',
  'JU OŠ "Musa Ćazim Ćatić"',
  'JU OŠ "Mustafa Busuladžić"',
  'JU OŠ "Nafija Sarajlić"',
  'JU OŠ "Osman Nakaš"',
  'JU OŠ "Osman Nuri Hadžić"',
  'JU OŠ "Podlugovi"',
  'JU OŠ "Pofalići"',
  'JU OŠ "Porodice ef. Ramić" Semizovac',
  'JU OŠ "Saburina"',
  'JU OŠ "Safvet-beg Bašagić"',
  'JU OŠ "Silvije Strahimir Kranjčević"',
  'JU OŠ "Skender Kulenović"',
  'JU OŠ "Sokolje"',
  'JU OŠ "Stari Ilijaš"',
  'JU OŠ "Šejh Muhamed ef. Hadžijamaković"',
  'JU OŠ "Šip"',
  'JU OŠ "Umihana Čuvidina"',
  'JU OŠ "Velešićki heroji"',
  'JU OŠ "Vladislav Skarić"',
  'JU OŠ "Vrhbosna"',
  'JU OŠ "Zahid Baručija"',
  'JU OŠ "Zajko Delić"'
];

const USER_CATEGORIES = [
  'Učenik',
  'Roditelj',
  'Nastavno osoblje',
  'Stručna služba',
  'Drugo'
];

const WORK_TYPES = [
  'Individualni rad',
  'Grupni rad',
  'Rad s nastavnicima',
  'Rad s roditeljima',
  'Rad sa stručnom službom'
];

const TEAM_MEMBERS = [
  'Psiholog',
  'Logoped',
  'Defektolog'
];

// Globalne reference
let accessToken = null;
let currentEditingRecord = null;

// Inicijalizacija pri učitavanju
window.onload = async function() {
  // 1. Provjeri da li postoji ?code= u URL-u (callback od Cognito-a)
  const urlParams = new URLSearchParams(window.location.search);
  const authCode = urlParams.get('code');
  const returnedState = urlParams.get('state');
  const errorParam = urlParams.get('error');
  
  // Ako ima error parametar, prikaži poruku
  if (errorParam) {
    const errorDescription = urlParams.get('error_description') || errorParam;
    console.error('Cognito error:', errorParam, errorDescription);
    alert('Greška pri prijavi: ' + errorDescription);
    
    // Očisti URL i prikaži login screen
    window.history.replaceState({}, document.title, window.location.pathname);
    showLoginScreen();
    return;
  }
  
  if (authCode) {
    // Provjeri state (CSRF zaštita)
    const savedState = sessionStorage.getItem('oauth_state');
    
    if (returnedState !== savedState) {
      console.error('State mismatch! Possible CSRF attack.');
      alert('Sigurnosna greška. Molimo pokušajte ponovo.');
      window.history.replaceState({}, document.title, window.location.pathname);
      showLoginScreen();
      return;
    }
    
    // State je validan - procesuiramo callback
    await handleCognitoCallback(authCode);
    return; // Exit jer ćemo redirectati nakon uspješnog tokena
  }

  // 2. Provjeri da li imamo token u localStorage
  // VAŽNO: Koristimo ID token jer sadrži custom attributes!
  accessToken = localStorage.getItem('id_token');
  
  if (!accessToken && REQUIRE_AUTH) {
    // Nema tokena - prikaži login screen
    showLoginScreen();
    return;
  }

  // 3. Token postoji - inicijalizuj aplikaciju
  initializeApp();
};

// Inicijalizacija glavne aplikacije
function initializeApp() {
  // Prvo provjeri da li uopšte imamo token
  if (!accessToken) {
    console.log('No ID token, user not logged in');
    showLoginScreen();
    return;
  }

  // Token postoji - parsiraj ga
  let decoded;
  try {
    decoded = parseJWT(accessToken);
  } catch (error) {
    console.error('Error parsing token:', error);
    // Token je nevalidan, očisti ga i prikaži login
    localStorage.removeItem('id_token');
    localStorage.removeItem('access_token');
    showLoginScreen();
    return;
  }

  // ✅ PROVJERA: Da li je token expired?
  const now = Math.floor(Date.now() / 1000);
  if (decoded.exp && decoded.exp < now) {
    const expiredDate = new Date(decoded.exp * 1000);
    console.warn('Token expired at:', expiredDate.toLocaleString());
    console.warn('Current time:', new Date(now * 1000).toLocaleString());
    
    // Token je istekao - obriši ga
    localStorage.removeItem('id_token');
    localStorage.removeItem('access_token');
    
    // Prikaži login screen
    showLoginScreen();
    
    // Prikaži poruku korisniku
    setTimeout(() => {
      showResultMessage('Vaša sesija je istekla. Molimo prijavite se ponovo.', 'error');
    }, 500);
    
    return;
  }

  // Token je validan - logiraj koliko još vrijedi
  const expiresIn = decoded.exp - now;
  const hoursLeft = Math.floor(expiresIn / 3600);
  const minutesLeft = Math.floor((expiresIn % 3600) / 60);
  console.log(`✅ Token valid for: ${hoursLeft}h ${minutesLeft}m`);
  console.log('Token expires at:', new Date(decoded.exp * 1000).toLocaleString());

  // Čitaj podatke iz ID tokena (sadrži custom attributes)
  const position = decoded['custom:position'] || decoded['profile']; // Fallback na 'profile' ako custom ima problem
  const homeSchool = decoded['custom:address']; // 
  const userRole = decoded['custom:role'];
  const firstName = decoded['given_name'] || decoded['name'] || '';
  const lastName = decoded['family_name'] || '';
  const email = decoded['email'];

  // Sačuvaj user podatke globalno
  currentUser = {
    firstName: firstName,
    lastName: lastName,
    email: email,
    position: position,
    homeSchool: homeSchool,
    role: userRole
  };

  console.log('User logged in:', currentUser);

  // 📦 Load cache from localStorage if available
  loadCacheFromStorage();

  // Nastavi sa inicijalizacijom
  hideLoginScreen();
  
  // Prikaži user info banner
  displayUserInfo(firstName, lastName, position, homeSchool);
  
  // Prikaži navigaciju (samo admin link za admina)
  setupNavigation(userRole);
  
  populateSelects();
  populateEditFormSelects();
  setTimestamp();
  setTodayDate();
  
  setupFormHandler();
  setupTabNavigation();
  setupHistoryHandlers();
  setupModalHandlers();
  setupLogoutHandler();
  
  // Setup conditional fields za radio buttons
  setupConditionalFields();
  
  // Prikaži logout dugme
  document.getElementById('logoutBtn').style.display = 'block';
}

// ===== CONDITIONAL FIELDS LOGIC =====

// 🔧 GLOBALNA funkcija za toggle conditional fields
// Da bi mogla biti pozvana iz resetForm() i drugih mjesta
function toggleConditionalFields() {
  const attendanceRadio = document.getElementById('attendance');
  const contactRadio = document.getElementById('contact');
  const attendanceTypeSelect = document.getElementById('attendanceType');
  const contactTypeSelect = document.getElementById('contactType');
  
  // Sva conditional polja (grupa DIV-ova)
  const conditionalGroups = [
    document.getElementById('userCategoryGroup'),
    document.getElementById('environmentGroup'),
    document.getElementById('initialsGroup')
  ];
  
  // Svi input/select elementi koji se disable
  const conditionalFields = [
    document.getElementById('userCategory'),
    document.getElementById('environment'),
    document.getElementById('initials')
  ];
  
  if (attendanceRadio && attendanceRadio.checked) {
    // PRISUSTVOVANJE izabrano
    if (attendanceTypeSelect) {
      attendanceTypeSelect.disabled = false;
      attendanceTypeSelect.required = true;
    }
    if (contactTypeSelect) {
      contactTypeSelect.disabled = true;
      contactTypeSelect.required = false;
    }
    
    // Zamrzni conditional groups (opacity + pointer-events)
    conditionalGroups.forEach(group => {
      if (group) {
        group.style.opacity = '0.5';
        group.style.pointerEvents = 'none';
      }
    });
    
    // Disable sva conditional polja i RESETUJ VRIJEDNOSTI
    conditionalFields.forEach(field => {
      if (field) {
        field.disabled = true;
        // Ukloni required samo za userCategory i environment
        if (field.id === 'userCategory' || field.id === 'environment') {
          field.required = false;
        }
        // VAŽNO: Resetuj vrijednost na prazan string
        if (field.tagName === 'SELECT') {
          field.value = '';
        } else if (field.tagName === 'INPUT') {
          field.value = '';
        }
      }
    });
    
  } else if (contactRadio && contactRadio.checked) {
    // KONTAKT RAD izabran (default)
    if (attendanceTypeSelect) {
      attendanceTypeSelect.disabled = true;
      attendanceTypeSelect.required = false;
    }
    if (contactTypeSelect) {
      contactTypeSelect.disabled = false;
      contactTypeSelect.required = true;
    }
    
    // Odmrzni conditional groups
    conditionalGroups.forEach(group => {
      if (group) {
        group.style.opacity = '1';
        group.style.pointerEvents = 'auto';
      }
    });
    
    // Enable sva conditional polja
    conditionalFields.forEach(field => {
      if (field) {
        field.disabled = false;
        // Postavi required za userCategory i environment
        if (field.id === 'userCategory' || field.id === 'environment') {
          field.required = true;
        }
      }
    });
  }
}

function setupConditionalFields() {
  const attendanceRadio = document.getElementById('attendance');
  const contactRadio = document.getElementById('contact');
  
  // Event listeners za radio buttons
  if (attendanceRadio) {
    attendanceRadio.addEventListener('change', toggleConditionalFields);
  }
  if (contactRadio) {
    contactRadio.addEventListener('change', toggleConditionalFields);
  }
  
  // 🔧 EKSPLICITNO postavi "Kontakt rad" kao checked nakon refresh-a
  // Da spriječimo zaleđena polja
  if (contactRadio && !attendanceRadio.checked) {
    contactRadio.checked = true;
  }
  
  // Inicijalizuj stanje (Kontakt rad je default)
  toggleConditionalFields();
}

// Prikaži user info banner
function displayUserInfo(firstName, lastName, position, homeSchool) {
  const banner = document.getElementById('userInfoBanner');
  const fullNameEl = document.getElementById('userFullName');
  const positionEl = document.getElementById('userPosition');
  const schoolEl = document.getElementById('userSchool');
  
  if (banner && fullNameEl && positionEl && schoolEl) {
    // Postavi podatke
    const fullName = firstName && lastName ? `${firstName} ${lastName}` : 'Korisnik';
    fullNameEl.textContent = fullName;
    positionEl.textContent = position || 'Nema podatke';
    schoolEl.textContent = homeSchool || 'Nema podatke';
    
    // Prikaži banner
    banner.style.display = 'block';
    
    console.log('✅ User info displayed:', { fullName, position, homeSchool });
  } else {
    console.warn('User info banner elements not found');
  }
}

// Setup navigacija sa admin linkom
function setupNavigation(userRole) {
  console.log('===== SETUP NAVIGATION DEBUG =====');
  console.log('userRole passed to setupNavigation:', userRole);
  
  // Nađi navigaciju (već postoji u HTML-u)
  const nav = document.getElementById('appNavigation');
  const adminLink = document.getElementById('adminNavLink');
  
  // Prikaži navigaciju SAMO za admina
  if (userRole === 'admin') {
    if (nav) {
      nav.style.display = 'flex';
      console.log('✅ Navigation displayed (user is admin)');
    }
    
    if (adminLink) {
      adminLink.style.display = 'inline-flex';
      console.log('✅ Admin link shown');
    }
  } else {
    // Obični korisnici - sakrij navigaciju potpuno
    if (nav) {
      nav.style.display = 'none';
      console.log('ℹ️ Navigation hidden (user is not admin)');
    }
  }
  
  console.log('==================================');
}

// Parse JWT token
function parseJWT(token) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
  } catch (error) {
    console.error('Error parsing JWT:', error);
    return {};
  }
}

// Auto-popuni polje "Član tima" i učini ga read-only
// Prikaži login screen
function showLoginScreen() {
  document.getElementById('authWarning').classList.add('show');
  document.getElementById('sessionForm').style.display = 'none';
  document.querySelector('.tabs').style.display = 'none';
  
  const loginBtn = document.getElementById('loginBtn');
  loginBtn.onclick = initiateLogin;
}

// Sakrij login screen
function hideLoginScreen() {
  document.getElementById('authWarning').classList.remove('show');
  document.getElementById('sessionForm').style.display = 'block';
  document.querySelector('.tabs').style.display = 'flex';
}

// Inicijalizacija login procesa sa PKCE
async function initiateLogin() {
  const verifier = b64url(randomBytes());
  sessionStorage.setItem('pkce_verifier', verifier);
  
  // Generiši random state za CSRF zaštitu
  const state = b64url(randomBytes());
  sessionStorage.setItem('oauth_state', state);
  
  const challenge = b64url(await sha256(new TextEncoder().encode(verifier)));

  const authUrl = new URL(`https://${COGNITO_DOMAIN}/oauth2/authorize`);
  authUrl.searchParams.set('client_id', COGNITO_CLIENT_ID);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('scope', SCOPE);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('code_challenge', challenge);

  console.log('=== INITIATING LOGIN ===');
  console.log('Redirect URI:', REDIRECT_URI);
  console.log('Client ID:', COGNITO_CLIENT_ID);
  console.log('Scope:', SCOPE);
  console.log('Auth URL:', authUrl.toString());
  console.log('========================');

  window.location.href = authUrl.toString();
}

// Obrada callback-a od Cognito-a
async function handleCognitoCallback(code) {
  const verifier = sessionStorage.getItem('pkce_verifier');
  
  if (!verifier) {
    alert('PKCE verifier nije pronađen. Molimo pokušajte ponovo.');
    window.location.href = window.location.pathname; // Clear URL
    return;
  }

  // Pripremi parametre za token exchange
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: COGNITO_CLIENT_ID,
    code: code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier
  });

  if (COGNITO_CLIENT_SECRET) {
    params.set('client_secret', COGNITO_CLIENT_SECRET);
  }

  // 🔍 DEBUG LOG - Request params
  console.log('=== TOKEN EXCHANGE REQUEST ===');
  console.log('Cognito domain:', COGNITO_DOMAIN);
  console.log('Client ID:', COGNITO_CLIENT_ID);
  console.log('Redirect URI:', REDIRECT_URI);
  console.log('Code:', code ? code.substring(0, 20) + '...' : 'MISSING');
  console.log('Code verifier:', verifier ? 'Present' : 'MISSING');
  console.log('Client secret:', COGNITO_CLIENT_SECRET ? 'Present' : 'Not used (Public client)');
  console.log('Full params:', params.toString());
  console.log('==============================');

  try {
    const response = await fetch(`https://${COGNITO_DOMAIN}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params
    });

    const data = await response.json();

    // 🔍 DETALJNI DEBUG LOG
    console.log('=== TOKEN EXCHANGE DEBUG ===');
    console.log('Response status:', response.status);
    console.log('Response OK:', response.ok);
    console.log('Response data:', data);
    console.log('Error (if any):', data.error);
    console.log('Error description:', data.error_description);
    console.log('===========================');

    if (!response.ok) {
      throw new Error(data.error_description || data.error || 'Token exchange failed');
    }

    // Spremi tokene u localStorage
    localStorage.setItem('access_token', data.access_token || '');
    localStorage.setItem('id_token', data.id_token || '');
    localStorage.setItem('refresh_token', data.refresh_token || '');

    // Očisti PKCE verifier
    sessionStorage.removeItem('pkce_verifier');

    // Očisti URL i reload stranicu
    window.history.replaceState({}, document.title, window.location.pathname);
    window.location.reload();

  } catch (error) {
    console.error('=== TOKEN EXCHANGE ERROR ===');
    console.error('Error object:', error);
    console.error('Error message:', error.message);
    console.error('============================');
    alert('Greška pri prijavi: ' + error.message);
    window.location.href = window.location.pathname;
  }
}

// Provjera autentikacije (samo update UI-a)
function checkAuth() {
  accessToken = localStorage.getItem('access_token');
  const submitBtn = document.getElementById('submitBtn');

  if (!accessToken && REQUIRE_AUTH) {
    submitBtn.disabled = true;
  } else {
    submitBtn.disabled = false;
  }
}

// Popunjavanje select polja
function populateSelects() {
  // School dropdown će biti populisan asinkrono sa top schools
  populateSmartSchoolDropdown();
  
  // userCategory, environment, attendanceType, contactType su hardkodirani u HTML-u
  // Ne trebaju se populisati dinamički
}

// Pametni dropdown za škole sa top 5
function populateSmartSchoolDropdown() {
  const selectEl = document.getElementById('school');
  
  // Dohvati top škole iz localStorage-a
  const topSchools = getTopSchoolsFromLocalStorage();
  
  // Očisti select
  selectEl.innerHTML = '<option value="">-- Odaberite školu --</option>';
  
  if (topSchools.length > 0) {
    // Kreiraj optgroup za često korištene škole
    const topGroup = document.createElement('optgroup');
    topGroup.label = '⭐ Često korištene';
    
    topSchools.forEach(schoolData => {
      const optEl = document.createElement('option');
      optEl.value = schoolData.school;
      optEl.textContent = schoolData.school;
      topGroup.appendChild(optEl);
    });
    
    selectEl.appendChild(topGroup);
    
    console.log('✅ Top schools loaded:', topSchools.length);
  }
  
  // Kreiraj optgroup za sve škole
  const allGroup = document.createElement('optgroup');
  allGroup.label = '📚 Sve škole';
  
  SCHOOLS.forEach(school => {
    const optEl = document.createElement('option');
    optEl.value = school;
    optEl.textContent = school;
    allGroup.appendChild(optEl);
  });
  
  selectEl.appendChild(allGroup);
}

// Dohvati top 5 škola iz localStorage-a
function getTopSchoolsFromLocalStorage() {
  try {
    const storedData = localStorage.getItem('schoolUsageStats');
    if (!storedData) {
      console.log('No school usage stats in localStorage yet');
      return [];
    }
    
    const stats = JSON.parse(storedData);
    
    // Sortiraj po broju korištenja (descending)
    const sortedSchools = Object.entries(stats)
      .map(([school, count]) => ({ school, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5); // Top 5
    
    console.log('Top schools from localStorage:', sortedSchools);
    return sortedSchools;
  } catch (error) {
    console.error('Error reading school stats from localStorage:', error);
    return [];
  }
}

// Ažuriraj statistiku korištenja škola nakon submita
function updateSchoolUsageStats(school) {
  if (!school) return;
  
  try {
    // Učitaj postojeće statistike
    const storedData = localStorage.getItem('schoolUsageStats');
    const stats = storedData ? JSON.parse(storedData) : {};
    
    // Inkrementiraj broj korištenja
    stats[school] = (stats[school] || 0) + 1;
    
    console.log('Updated school stats:', stats);
    
    // Sačuvaj natrag u localStorage
    localStorage.setItem('schoolUsageStats', JSON.stringify(stats));
    
    console.log('✅ School usage stats updated for:', school);
  } catch (error) {
    console.error('Error updating school stats:', error);
  }
}

// Ažuriraj statistiku iz historije (bulk update)
function updateSchoolStatsFromHistory(sessions) {
  if (!sessions || sessions.length === 0) return;
  
  try {
    const stats = {};
    
    // Izbroj sve škole iz historije
    sessions.forEach(session => {
      const school = session.school;
      if (school) {
        stats[school] = (stats[school] || 0) + 1;
      }
    });
    
    console.log('Calculated stats from history:', stats);
    
    // Sačuvaj u localStorage
    localStorage.setItem('schoolUsageStats', JSON.stringify(stats));
    
    console.log('✅ School stats synced from history');
    
    // Re-populate dropdown sa novim top školama
    populateSmartSchoolDropdown();
  } catch (error) {
    console.error('Error updating stats from history:', error);
  }
}

function populateSelect(id, options) {
  const select = document.getElementById(id);
  options.forEach(option => {
    const optEl = document.createElement('option');
    optEl.value = option;
    optEl.textContent = option;
    select.appendChild(optEl);
  });
}

// Popunjavanje select polja u edit formi
function populateEditFormSelects() {
  // Samo škola je potrebna u edit modalu - ostalo su radio buttons i conditional polja
  populateSelect('edit-school', SCHOOLS);
  // edit-userCategory, edit-workType više nisu obični select-i
  // edit-minutes je sada dropdown i već ima opcije u HTML-u
}

// Postavljanje vremenske oznake
function setTimestamp() {
  const timestamp = new Date().toISOString();
  document.getElementById('timestamp').value = timestamp;
}

// Postavljanje današnjeg datuma
function setTodayDate() {
  const today = new Date().toISOString().split('T')[0];
  document.getElementById('activityDate').value = today;
}

// Setup event listener za formu
function setupFormHandler() {
  const form = document.getElementById('sessionForm');
  form.addEventListener('submit', handleSubmit);
}

// Obrada submita
async function handleSubmit(e) {
  e.preventDefault();
  
  clearErrors();
  hideResultMessage();

  const data = getFormData();
  const errors = validateData(data);

  if (Object.keys(errors).length > 0) {
    renderErrors(errors);
    return;
  }

  await submitData(data);
}

// Prikupljanje podataka iz forme
function getFormData() {
  // Provjeri koji tip aktivnosti je izabran
  const activityType = document.querySelector('input[name="activityType"]:checked')?.value;
  
  let userCategory = '';
  let workType = '';
  
  if (activityType === 'attendance') {
    // PRISUSTVOVANJE
    const attendanceType = document.getElementById('attendanceType')?.value;
    
    // VAŽNO: userCategory MORA biti prazan string za prisustvovanje
    userCategory = '';
    
    // Mapiraj attendanceType u čitljiv tekst
    const attendanceLabels = {
      'odjeljenskom_vijecu': 'Odjeljenskom vijeću škole',
      'nastavnickom_vijecu': 'Nastavničkom vijeću škole',
      'multisektorskom_sastanku': 'Multisektorskom sastanku'
    };
    
    workType = attendanceType ? `Prisustvovanje - ${attendanceLabels[attendanceType] || attendanceType}` : 'Prisustvovanje';
    
  } else if (activityType === 'contact') {
    // KONTAKT RAD
    const contactType = document.getElementById('contactType')?.value;
    
    // Pročitaj userCategory SAMO ako je kontakt rad
    const userCategoryField = document.getElementById('userCategory');
    const userCategoryValue = (userCategoryField && !userCategoryField.disabled) ? userCategoryField.value : '';
    
    // Mapiraj userCategory u čitljiv tekst
    const userCategoryLabels = {
      's_ucenikom': 'S učenikom',
      's_roditeljima': 'S roditeljima',
      's_nastavnikom': 'S nastavnikom',
      's_nastavnicima': 'S nastavnicima',
      's_uciteljem': 'S učiteljem',
      's_uciteljima': 'S učiteljima',
      's_strucnom_sluzbom': 'S stručnom službom'
    };
    
    userCategory = userCategoryLabels[userCategoryValue] || userCategoryValue;
    
    // Mapiraj contactType u čitljiv tekst - OBRNUTI REDOSLIJED
    const contactLabels = {
      'direktni': 'Direktni kontakt rad',
      'online': 'Online kontakt rad'
    };
    
    workType = contactLabels[contactType] || 'Kontakt rad';
  }
  
  // Prikupi environment i initials za note (opcionalno)
  const environmentField = document.getElementById('environment');
  const initialsField = document.getElementById('initials');
  const noteField = document.getElementById('note');
  
  const environmentValue = (environmentField && !environmentField.disabled) ? environmentField.value : '';
  const initials = (initialsField && !initialsField.disabled) ? initialsField.value?.trim() : '';
  const additionalNote = noteField ? noteField.value?.trim() : '';
  
  // Mapiraj environment u čitljiv tekst (lowercase)
  const envLabels = {
    'individualno': 'individualno',
    'u_grupi': 'u grupi'
  };
  const environment = envLabels[environmentValue] || environmentValue;
  
  // Kombinuj note sa environment i initials ako postoje
  let finalNote = '';
  const noteParts = [];
  
  if (activityType === 'contact') {
    if (environment) {
      noteParts.push(environment);  // Samo "individualno" ili "u grupi"
    }
    if (initials) {
      noteParts.push(initials);  // Samo inicijali bez labele
    }
  }
  
  if (additionalNote) {
    noteParts.push(additionalNote);
  }
  
  // Separator je " | " ako ima više dijelova
  finalNote = noteParts.join(' | ');
  
  return {
    // Podaci iz forme
    timestamp: document.getElementById('timestamp').value,
    activityDate: document.getElementById('activityDate').value,
    school: document.getElementById('school').value,
    userCategory: userCategory,  // Prazan string za Prisustvovanje, čitljiv tekst za Kontakt rad
    workType: workType,
    note: finalNote,
    hours: parseInt(document.getElementById('minutes').value, 10),
    teamMember: currentUser.position, // Koristi poziciju iz tokena
    
    // User podaci iz ID tokena
    userFirstName: currentUser.firstName,
    userLastName: currentUser.lastName,
    userEmail: currentUser.email,
    userPosition: currentUser.position,
    userHomeSchool: currentUser.homeSchool,
    userRole: currentUser.role
  };
}

// Validacija podataka
function validateData(data, context = 'main') {
  const errors = {};

  if (!data.activityDate) {
    errors.activityDate = 'Datum aktivnosti je obavezan.';
  }

  if (!data.school) {
    errors.school = 'Škola je obavezna.';
  }

  // Određi prefix za IDs ovisno o kontekstu
  const prefix = context === 'edit' ? 'edit-' : '';
  const radioName = context === 'edit' ? 'edit-activityType' : 'activityType';
  
  // Provjeri koji tip aktivnosti je izabran
  const activityType = document.querySelector(`input[name="${radioName}"]:checked`)?.value;
  
  if (!activityType) {
    errors.activityType = 'Morate izabrati tip aktivnosti (Prisustvovanje ili Kontakt rad).';
  }
  
  if (activityType === 'attendance') {
    // PRISUSTVOVANJE - provjeri attendanceType
    const attendanceType = document.getElementById(`${prefix}attendanceType`)?.value;
    if (!attendanceType) {
      errors.attendanceType = 'Morate izabrati tip prisustvovanja.';
    }
  } else if (activityType === 'contact') {
    // KONTAKT RAD - provjeri userCategory, environment i contactType
    if (!data.userCategory) {
      errors.userCategory = 'Kategorija korisnika je obavezna za kontakt rad.';
    }
    
    const environment = document.getElementById(`${prefix}environment`)?.value;
    if (!environment) {
      errors.environment = 'Okruženje je obavezno za kontakt rad.';
    }
    
    const contactType = document.getElementById(`${prefix}contactType`)?.value;
    if (!contactType) {
      errors.contactType = 'Tip kontakta je obavezan.';
    }
  }

  // Note je sada opcionalno - ne provjeravamo
  // Ali ako postoji, ograničimo dužinu
  if (data.note && data.note.length > 500) {
    errors.note = 'Napomena može imati maksimalno 500 znakova.';
  }

  const duration = data.minutes || data.hours;
  if (isNaN(duration) || duration < 1) {
    errors.minutes = 'Trajanje je obavezno.';
  }

  return errors;
}

// Prikaz grešaka
function renderErrors(errors) {
  // Prikaži malu validation poruku iznad dugmeta
  const formErrorEl = document.getElementById('formValidationError');
  if (formErrorEl) {
    formErrorEl.textContent = 'Niste popunili sva obavezna polja';
    formErrorEl.classList.add('show');
  }
  
  // Prikaži pojedinačne field errore
  for (const field in errors) {
    const errorEl = document.getElementById('error-' + field);
    if (errorEl) {
      errorEl.textContent = errors[field];
      errorEl.classList.add('show');
    }
  }
}

// Čišćenje grešaka
function clearErrors() {
  const errorElements = document.querySelectorAll('.field-error');
  errorElements.forEach(el => {
    el.textContent = '';
    el.classList.remove('show');
  });
  
  // Očisti i form validation error
  const formErrorEl = document.getElementById('formValidationError');
  if (formErrorEl) {
    formErrorEl.textContent = '';
    formErrorEl.classList.remove('show');
  }
}

// NAPOMENA: showValidationWarning i hideValidationWarning više nisu potrebni
// jer koristimo field-error stil za validation poruku

// Slanje podataka
async function submitData(data) {
  setLoading(true);

  // ✅ SAFETY CHECK 1: Provjeri da li token postoji
  if (!accessToken) {
    console.error('No token found during submit');
    showResultMessage('Niste prijavljeni. Molimo prijavite se ponovo.', 'error');
    showLoginScreen();
    setLoading(false);
    return;
  }

  // ✅ SAFETY CHECK 2: Provjeri da li je token expired
  try {
    const decoded = parseJWT(accessToken);
    const now = Math.floor(Date.now() / 1000);
    
    if (decoded.exp && decoded.exp < now) {
      console.error('Token expired during submit');
      console.error('Expired at:', new Date(decoded.exp * 1000).toLocaleString());
      
      // Obriši expired token
      localStorage.removeItem('id_token');
      localStorage.removeItem('access_token');
      
      // Prikaži poruku i preusmjeri na login
      showResultMessage('Vaša sesija je istekla. Preusmjeravam na login...', 'error');
      
      setTimeout(() => {
        window.location.href = getAuthorizationUrl();
      }, 2000);
      
      setLoading(false);
      return;
    }
    
    // Log koliko još vrijedi
    const expiresIn = decoded.exp - now;
    console.log(`Token valid for ${Math.floor(expiresIn / 60)} more minutes`);
    
  } catch (error) {
    console.error('Token validation failed:', error);
    showResultMessage('Greška pri provjeri sesije. Molimo prijavite se ponovo.', 'error');
    localStorage.removeItem('id_token');
    localStorage.removeItem('access_token');
    showLoginScreen();
    setLoading(false);
    return;
  }

  // Token je validan - nastavi sa slanjem
  try {
    const headers = {
      'Content-Type': 'application/json'
    };

    if (REQUIRE_AUTH && accessToken) {
      headers['Authorization'] = 'Bearer ' + accessToken;
    }

    const response = await fetch(N8N_WEBHOOK_URL, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(data)
    });

    if (!response.ok) {
      let errorMsg = 'Greška pri slanju: ' + response.status;
      
      // Posebna obrada za authentication greške
      if (response.status === 401 || response.status === 403) {
        try {
          const errorData = await response.json();
          if (errorData.message && (errorData.message.includes('expired') || errorData.message.includes('invalid'))) {
            errorMsg = 'Vaša sesija je istekla. Molimo prijavite se ponovo.';
            localStorage.removeItem('id_token');
            localStorage.removeItem('access_token');
            
            setTimeout(() => {
              window.location.href = getAuthorizationUrl();
            }, 2000);
          }
        } catch (e) {
          // Ignore JSON parse error
        }
      } else {
        try {
          const errorData = await response.json();
          if (errorData.message) {
            errorMsg = errorData.message;
          }
        } catch (e) {
          // Ignorišemo ako ne možemo parsirati JSON
        }
      }
      
      throw new Error(errorMsg);
    }

    // Uspješno slanje
    showResultMessage('Evidencija je uspješno poslata!', 'success');
    
    // Ažuriraj statistiku korištenja škola
    updateSchoolUsageStats(data.school);
    
    // 🗑️ INVALIDATE CACHE
    // Obriši sve cache podatke jer smo dodali novi unos
    console.log('🗑️ Invalidating all cache after successful submit...');
    historyCache = {}; // Resetuj in-memory cache
    localStorage.removeItem('history_cache'); // Obriši localStorage cache
    
    // 🚀 FORCE CACHE REFRESH + AUTO-RELOAD HISTORY
    // Čekamo 2s da Google Sheets zapiše, pa refresh-ujemo cache
    // Ako je history tab aktivan, automatski reload-ujemo
    console.log('📦 Refreshing cache in 2 seconds...');
    setTimeout(async () => {
      await refreshHistoryCacheInBackground();
      
      // Ako je history tab trenutno aktivan, reload-uj ga
      const historySection = document.getElementById('historySection');
      const isHistoryVisible = historySection && !historySection.classList.contains('hidden');
      
      if (isHistoryVisible) {
        console.log('🔄 Auto-reloading history tab after cache refresh...');
        // Pronađi koji filter je aktivan
        const activeButton = document.querySelector('#filterButtons button.active');
        if (activeButton) {
          const activeFilter = activeButton.dataset.filter;
          console.log(`🔄 Reloading active filter: ${activeFilter}`);
          await loadHistory(activeFilter);
        }
      }
    }, 2000);
    
    resetForm();

  } catch (error) {
    console.error('Submit error:', error);
    showResultMessage('Greška: ' + error.message, 'error');
  } finally {
    setLoading(false);
  }
}

// Postavljanje stanja učitavanja
function setLoading(isLoading) {
  const submitBtn = document.getElementById('submitBtn');
  
  if (isLoading) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Šaljem...';
  } else {
    if (!REQUIRE_AUTH || accessToken) {
      submitBtn.disabled = false;
    }
    submitBtn.textContent = 'Pošalji evidenciju';
  }
}

// Prikaz poruke o rezultatu
function showResultMessage(message, type) {
  const resultEl = document.getElementById('resultMessage');
  resultEl.textContent = message;
  resultEl.className = 'result-message show ' + type;
}

// Sakrivanje poruke o rezultatu
function hideResultMessage() {
  const resultEl = document.getElementById('resultMessage');
  resultEl.className = 'result-message';
  resultEl.textContent = '';
}

// Reset forme
function resetForm() {
  const form = document.getElementById('sessionForm');
  form.reset();
  
  // Ponovno postavi timestamp i datum
  setTimestamp();
  setTodayDate();
  
  clearErrors();
  
  // 🔧 BITNO: Resetuj radio buttons na default i odmrzni polja
  // Koristimo setTimeout da osiguramo da browser završi sa reset-om prije nego što pozovemo toggle
  setTimeout(() => {
    const contactRadio = document.getElementById('contact');
    if (contactRadio) {
      contactRadio.checked = true;
    }
    
    // Direktno pozovi toggleConditionalFields da aktivira polja
    if (typeof toggleConditionalFields === 'function') {
      toggleConditionalFields();
    }
  }, 10); // Samo 10ms pauza - dovoljno da browser završi reset
}

// ===== TAB NAVIGACIJA =====

function setupTabNavigation() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.getAttribute('data-tab');
      switchTab(tabName);
    });
  });
}

function switchTab(tabName) {
  // Ukloni active klasu sa svih tabova
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.remove('active');
  });
  document.querySelectorAll('.tab-content').forEach(content => {
    content.classList.remove('active');
  });

  // Dodaj active klasu na odabrani tab
  document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
  document.getElementById(`tab-${tabName}`).classList.add('active');

  // Ako je odabran history tab, učitaj podatke sa default "today" filterom
  if (tabName === 'history') {
    loadHistoryTab('today'); // ← Koristi loadHistoryTab sa default filterom
  }
}

// ===== HISTORY (RANIJI UNOSI) =====

function setupHistoryHandlers() {
  // History tab buttons su postavljeni u HTML-u sa onclick="loadHistoryTab('...')"
  // Kad se prvi put otvori History tab, switchTab() će pozvati loadHistoryTab('today')
  console.log('History handlers setup complete');
}

// Funkcija za učitavanje historije sa određenim filter-om i aktiviranje taba
function loadHistoryTab(filter) {
  // Deaktiviraj sve tab-ove
  document.querySelectorAll('.history-tab').forEach(tab => {
    tab.classList.remove('active');
  });
  
  // Aktiviraj odabrani tab
  const activeTab = document.getElementById(`tab-${filter.replace('_', '-')}`);
  if (activeTab) {
    activeTab.classList.add('active');
  }
  
  // Učitaj podatke
  loadHistory(filter);
}

async function loadHistory(filter = 'today') {
  showLoadingState();

  try {
    // 🚀 CHECK CACHE FIRST
    if (CACHE_CONFIG.enabled) {
      const cached = historyCache[filter];
      const now = Date.now();
      
      if (cached && cached.data && cached.timestamp) {
        const age = now - cached.timestamp;
        
        if (age < CACHE_CONFIG.duration) {
          console.log(`📦 Cache HIT for "${filter}" (age: ${Math.round(age/1000)}s)`);
          
          const sessions = cached.data;
          
          if (sessions.length === 0) {
            showEmptyState(filter);
          } else {
            updateSchoolStatsFromHistory(sessions);
            renderHistoryTable(sessions);
          }
          
          return; // Exit early - using cached data!
        } else {
          console.log(`📦 Cache STALE for "${filter}" (age: ${Math.round(age/1000)}s)`);
        }
      } else {
        console.log(`📦 Cache MISS for "${filter}"`);
      }
    }
    
    // Cache miss or disabled - fetch from backend
    console.log('🌐 Fetching from backend...');
    
    const headers = {
      'Content-Type': 'application/json'
    };

    if (REQUIRE_AUTH && accessToken) {
      headers['Authorization'] = 'Bearer ' + accessToken;
    }

    // Dodaj filter u URL kao query parameter
    const url = `${N8N_HISTORY_URL}?filter=${filter}`;

    console.log('=== LOADING HISTORY ===');
    console.log('Filter:', filter);
    console.log('URL:', url);

    const response = await fetch(url, {
      method: 'GET',
      headers: headers
    });

    console.log('Response status:', response.status);

    if (!response.ok) {
      throw new Error('Greška pri učitavanju podataka: ' + response.status);
    }

    // Provjeri da li response ima sadržaj prije parsiranja
    const responseText = await response.text();
    console.log('Response text length:', responseText.length);
    
    let data;
    if (!responseText || responseText.trim() === '') {
      // Prazan response - tretirati kao prazan niz
      console.log('Empty response, treating as no sessions');
      data = [];
    } else {
      try {
        data = JSON.parse(responseText);
      } catch (parseError) {
        console.error('JSON parse error:', parseError);
        console.error('Response text:', responseText);
        // Ako nije validan JSON, tretirati kao prazan niz
        data = [];
      }
    }
    
    // n8n može vratiti podatke na različite načine
    let sessions = [];
    
    if (Array.isArray(data)) {
      sessions = data;
    } else if (data && Array.isArray(data.sessions)) {
      sessions = data.sessions;
    } else if (data && typeof data === 'object') {
      sessions = [data];
    }

    // Filtriraj prazne objekte (n8n ponekad vrati [{}] umjesto [])
    sessions = sessions.filter(session => {
      return session.activityDate || session.school || session.timestamp;
    });
    
    console.log('Sessions after filtering:', sessions.length);

    // 🚀 UPDATE CACHE
    if (CACHE_CONFIG.enabled) {
      historyCache[filter] = {
        data: sessions,
        timestamp: Date.now()
      };
      console.log(`📦 Cache UPDATED for "${filter}"`);
      
      // Persist to localStorage (optional - survives page reload)
      try {
        localStorage.setItem(CACHE_CONFIG.storageKey, JSON.stringify(historyCache));
      } catch (e) {
        console.warn('Failed to persist cache to localStorage:', e);
      }
    }

    if (sessions.length === 0) {
      console.log('No sessions found, showing empty state');
      showEmptyState(filter);
    } else {
      console.log('Rendering', sessions.length, 'sessions');
      
      // Ažuriraj statistiku škola iz historije (bulk update)
      updateSchoolStatsFromHistory(sessions);
      
      renderHistoryTable(sessions);
    }

  } catch (error) {
    console.error('=== HISTORY LOAD ERROR ===');
    console.error('Error name:', error.name);
    console.error('Error message:', error.message);
    console.error('Full error:', error);
    
    showEmptyState(filter);
    
    // Prikaži alert samo za prave greške, ne za prazan response
    if (error.message && !error.message.includes('JSON')) {
      alert('Greška pri učitavanju historije: ' + error.message);
    }
  }
}

function showLoadingState() {
  document.getElementById('loadingState').classList.add('show');
  document.getElementById('emptyState').classList.remove('show');
  document.getElementById('tableWrapper').classList.remove('show');
}

function showEmptyState(filter = 'today') {
  document.getElementById('loadingState').classList.remove('show');
  document.getElementById('emptyState').classList.add('show');
  document.getElementById('tableWrapper').classList.remove('show');
  
  // Dinamički tekst zavisno od filter-a
  const emptyStateEl = document.getElementById('emptyState');
  let message = '';
  
  if (filter === 'today') {
    message = 'Nemate unosa za danas.';
  } else if (filter === 'current_month') {
    message = 'Nemate unosa za tekući mjesec.';
  } else if (filter === 'previous_month') {
    message = 'Nemate unosa za prethodni mjesec.';
  } else {
    message = 'Nemate još unesenih evidencija.';
  }
  
  emptyStateEl.innerHTML = `<p>${message}</p>`;
}

function showTableState() {
  document.getElementById('loadingState').classList.remove('show');
  document.getElementById('emptyState').classList.remove('show');
  document.getElementById('tableWrapper').classList.add('show');
}

// ===== FORMATIRANJE "RAD" KOLONE =====
function formatWorkDescription(session) {
  const workType = session.workType || '';
  const userCategory = session.userCategory || '';
  const note = session.note || '';
  
  // Parsiraj note da izvučemo environment i inicijale
  // Note format: "individualno | A.B." ili "u grupi | J.K. | dodatna napomena"
  const noteParts = note.split(' | ').map(part => part.trim()).filter(part => part);
  
  let environment = '';
  let initials = '';
  let additionalNote = '';
  
  // Detektuj environment (prvi dio koji je "individualno" ili "u grupi")
  if (noteParts.length > 0) {
    const firstPart = noteParts[0].toLowerCase();
    if (firstPart === 'individualno' || firstPart === 'u grupi') {
      environment = noteParts[0];
      noteParts.shift(); // Ukloni environment iz niza
    }
  }
  
  // Detektuj inicijale (kratki string sa tačkom, npr "A.B.")
  if (noteParts.length > 0) {
    const possibleInitials = noteParts[0];
    // Provjeri da li izgleda kao inicijali (1-5 karaktera sa tačkom)
    if (possibleInitials.length <= 5 && possibleInitials.includes('.')) {
      initials = possibleInitials;
      noteParts.shift(); // Ukloni inicijale iz niza
    }
  }
  
  // Što god ostane je dodatna napomena
  additionalNote = noteParts.join(' | ');
  
  // Sastavi opis
  const parts = [];
  
  // 1. WorkType (obavezno)
  if (workType) {
    parts.push(workType);
  }
  
  // 2. UserCategory (ako postoji i nije prazan)
  if (userCategory && userCategory.trim() !== '') {
    // Pretvori "S učenikom" u "s učenikom" (lowercase 's')
    const categoryLower = userCategory.replace(/^S\s/, 's ');
    parts.push(categoryLower);
  }
  
  // 3. Environment (ako postoji)
  if (environment) {
    parts.push(environment);
  }
  
  // 4. Inicijali (ako postoje)
  if (initials) {
    parts.push(initials);
  }
  
  // 5. Dodatna napomena (ako postoji) - stavimo u zagradu
  if (additionalNote) {
    parts.push(`(${additionalNote})`);
  }
  
  return parts.join(' ') || 'N/A';
}

function renderHistoryTable(sessions) {
  const tbody = document.getElementById('historyTableBody');
  tbody.innerHTML = '';

  sessions.forEach(session => {
    const row = document.createElement('tr');
    
    // Koristi activityDate umjesto timestamp-a
    const activityDate = session.activityDate || (session.timestamp ? new Date(session.timestamp).toISOString().split('T')[0] : 'N/A');
    const school = session.school || 'N/A';
    const hours = session.hours || session.minutes || 0;
    const sessionId = session.id || session.timestamp || session.row_number;
    
    // Formatiraj "Rad" kolonu - kombinacija workType + userCategory + note
    const workDescription = formatWorkDescription(session);
    
    row.innerHTML = `
      <td>${formatDate(activityDate)}</td>
      <td>${school}</td>
      <td>${workDescription}</td>
      <td>${hours} min</td>
      <td>
        <div class="action-buttons">
          <button class="btn-icon btn-edit" onclick="editRecord('${sessionId}')">
            ✎ Uredi
          </button>
          <button class="btn-icon btn-delete" onclick="deleteRecord('${sessionId}')">
            🗑 Obriši
          </button>
        </div>
      </td>
    `;

    // Spremimo cijeli objekt u data atribut za lakši pristup
    row.dataset.session = JSON.stringify(session);
    
    tbody.appendChild(row);
  });

  showTableState();
}

function formatDate(dateString) {
  const date = new Date(dateString);
  const day = String(date.getDate()).padStart(2, '0');
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const year = date.getFullYear();
  return `${day}.${month}.${year}`;
}

// ===== EDIT I DELETE AKCIJE =====

function editRecord(id) {
  // Pronađi zapis u tabeli
  const rows = document.querySelectorAll('#historyTableBody tr');
  let session = null;

  rows.forEach(row => {
    const data = JSON.parse(row.dataset.session);
    if ((data.id || data._id || data.timestamp) === id) {
      session = data;
    }
  });

  if (session) {
    currentEditingRecord = session;
    openEditModal(session);
  }
}


async function deleteRecord(id) {
  if (!confirm('Da li ste sigurni da želite obrisati ovu evidenciju?')) {
    return;
  }

  // 🔒 Pronađi red (tr) koji sadrži ovaj ID i disable cijeli red
  const rows = document.querySelectorAll('#historyTableBody tr');
  let targetRow = null;
  
  rows.forEach(row => {
    const sessionData = JSON.parse(row.dataset.session);
    const rowId = sessionData.id || sessionData.timestamp || sessionData.row_number;
    if (rowId === id) {
      targetRow = row;
    }
  });

  // Disable cijeli red
  if (targetRow) {
    targetRow.style.opacity = '0.5';
    targetRow.style.pointerEvents = 'none';
    
    // Promijeni tekst dugmeta
    const deleteBtn = targetRow.querySelector('.btn-delete');
    if (deleteBtn) {
      deleteBtn.textContent = '⏳ Brišem...';
    }
  }

  try {
    const headers = {
      'Content-Type': 'application/json'
    };

    if (REQUIRE_AUTH && accessToken) {
      headers['Authorization'] = 'Bearer ' + accessToken;
    }

    const response = await fetch(N8N_DELETE_URL, {
      method: 'DELETE',
      headers: headers,
      body: JSON.stringify({ id: id })
    });

    if (!response.ok) {
      throw new Error('Greška pri brisanju: ' + response.status);
    }

    // 🔥 INVALIDATE CACHE
    historyCache = {};
    if (CACHE_CONFIG.enabled) {
      localStorage.removeItem(CACHE_CONFIG.storageKey);
    }

    // REFRESH trenutnog aktivnog tab-a
    const activeTab = document.querySelector('.history-tab.active');
    
    if (activeTab) {
      const tabId = activeTab.id;
      
      if (tabId === 'tab-today') {
        await loadHistoryTab('today');
      } else if (tabId === 'tab-current-month') {
        await loadHistoryTab('current_month');
      } else if (tabId === 'tab-previous-month') {
        await loadHistoryTab('previous_month');
      }
    }
    
    alert('Evidencija je uspješno obrisana! ✅');

  } catch (error) {
    console.error('Greška:', error);
    alert('Greška pri brisanju: ' + error.message);
    
    // ✅ Re-enable red ako dođe do greške
    if (targetRow) {
      targetRow.style.opacity = '1';
      targetRow.style.pointerEvents = 'auto';
      
      const deleteBtn = targetRow.querySelector('.btn-delete');
      if (deleteBtn) {
        deleteBtn.textContent = '🗑 Obriši';
      }
    }
  }
}

// ===== MODAL ZA UREĐIVANJE =====

function setupModalHandlers() {
  const modal = document.getElementById('editModal');
  const closeBtn = document.getElementById('closeModal');
  const cancelBtn = document.getElementById('cancelEdit');
  const editForm = document.getElementById('editForm');

  // Zatvori modal
  closeBtn.addEventListener('click', closeEditModal);
  cancelBtn.addEventListener('click', closeEditModal);

  // Zatvori modal klikom van sadržaja
  modal.addEventListener('click', (e) => {
    if (e.target === modal) {
      closeEditModal();
    }
  });

  // Submit edit forme
  editForm.addEventListener('submit', handleEditSubmit);
}

// Setup radio button handlers za edit modal
function setupEditModalRadioHandlers() {
  const attendanceRadio = document.getElementById('edit-attendance');
  const contactRadio = document.getElementById('edit-contact');
  
  // Ukloni stare event listenere
  const newAttendanceRadio = attendanceRadio.cloneNode(true);
  const newContactRadio = contactRadio.cloneNode(true);
  attendanceRadio.parentNode.replaceChild(newAttendanceRadio, attendanceRadio);
  contactRadio.parentNode.replaceChild(newContactRadio, contactRadio);
  
  // Dodaj nove event listenere
  document.getElementById('edit-attendance').addEventListener('change', toggleEditModalConditionalFields);
  document.getElementById('edit-contact').addEventListener('change', toggleEditModalConditionalFields);
}

// Toggle conditional fields u edit modalu
function toggleEditModalConditionalFields() {
  const attendanceRadio = document.getElementById('edit-attendance');
  const contactRadio = document.getElementById('edit-contact');
  const attendanceTypeSelect = document.getElementById('edit-attendanceType');
  const contactTypeSelect = document.getElementById('edit-contactType');
  
  const conditionalGroups = [
    document.getElementById('edit-userCategoryGroup'),
    document.getElementById('edit-environmentGroup'),
    document.getElementById('edit-initialsGroup')
  ];
  
  const conditionalFields = [
    document.getElementById('edit-userCategory'),
    document.getElementById('edit-environment'),
    document.getElementById('edit-initials')
  ];
  
  if (attendanceRadio && attendanceRadio.checked) {
    // PRISUSTVOVANJE
    attendanceTypeSelect.disabled = false;
    attendanceTypeSelect.required = true;
    contactTypeSelect.disabled = true;
    contactTypeSelect.required = false;
    
    // Zamrzni conditional polja
    conditionalGroups.forEach(group => {
      if (group) {
        group.style.opacity = '0.5';
        group.style.pointerEvents = 'none';
      }
    });
    
    conditionalFields.forEach(field => {
      if (field) {
        field.disabled = true;
        if (field.id === 'edit-userCategory' || field.id === 'edit-environment') {
          field.required = false;
        }
        if (field.tagName === 'SELECT') {
          field.value = '';
        } else if (field.tagName === 'INPUT') {
          field.value = '';
        }
      }
    });
    
  } else if (contactRadio && contactRadio.checked) {
    // KONTAKT RAD
    attendanceTypeSelect.disabled = true;
    attendanceTypeSelect.required = false;
    contactTypeSelect.disabled = false;
    contactTypeSelect.required = true;
    
    // Odmrzni conditional polja
    conditionalGroups.forEach(group => {
      if (group) {
        group.style.opacity = '1';
        group.style.pointerEvents = 'auto';
      }
    });
    
    conditionalFields.forEach(field => {
      if (field) {
        field.disabled = false;
        if (field.id === 'edit-userCategory' || field.id === 'edit-environment') {
          field.required = true;
        }
      }
    });
  }
}

function openEditModal(session) {
  // Popuni osnovna polja
  document.getElementById('edit-id').value = session.id || session.timestamp || session._id;
  document.getElementById('edit-activityDate').value = session.activityDate;
  document.getElementById('edit-school').value = session.school;
  document.getElementById('edit-minutes').value = session.hours || session.minutes;
  
  // 🔍 PARSIRANJE workType i userCategory da odredimo tip aktivnosti
  const workType = session.workType || '';
  const userCategory = session.userCategory || '';
  
  // Provjeri da li je PRISUSTVOVANJE
  const isPrisustvovanje = workType.includes('Prisustvovanje');
  
  if (isPrisustvovanje) {
    // PRISUSTVOVANJE - radio button
    document.getElementById('edit-attendance').checked = true;
    document.getElementById('edit-contact').checked = false;
    
    // Parsiraj attendance tip iz workType
    // "Prisustvovanje - Odjeljenskom vijeću škole" → "odjeljenskom_vijecu"
    let attendanceType = '';
    if (workType.includes('Odjeljenskom vijeću')) {
      attendanceType = 'odjeljenskom_vijecu';
    } else if (workType.includes('Nastavničkom vijeću')) {
      attendanceType = 'nastavnickom_vijecu';
    } else if (workType.includes('Multisektorskom sastanku')) {
      attendanceType = 'multisektorskom_sastanku';
    }
    
    document.getElementById('edit-attendanceType').value = attendanceType;
    document.getElementById('edit-attendanceType').disabled = false;
    document.getElementById('edit-contactType').disabled = true;
    
    // Disable conditional polja
    document.getElementById('edit-userCategory').disabled = true;
    document.getElementById('edit-environment').disabled = true;
    document.getElementById('edit-initials').disabled = true;
    document.getElementById('edit-userCategory').required = false;
    document.getElementById('edit-environment').required = false;
    
    // Postavi opacity
    document.getElementById('edit-userCategoryGroup').style.opacity = '0.5';
    document.getElementById('edit-environmentGroup').style.opacity = '0.5';
    document.getElementById('edit-initialsGroup').style.opacity = '0.5';
    
  } else {
    // KONTAKT RAD - radio button
    document.getElementById('edit-contact').checked = true;
    document.getElementById('edit-attendance').checked = false;
    
    // Parsiraj contact tip iz workType
    // "Direktni kontakt rad" → "direktni"
    // "Online kontakt rad" → "online"
    let contactType = 'direktni'; // default
    if (workType.includes('Online')) {
      contactType = 'online';
    }
    
    document.getElementById('edit-contactType').value = contactType;
    document.getElementById('edit-contactType').disabled = false;
    document.getElementById('edit-attendanceType').disabled = true;
    
    // Parsiraj userCategory iz čitljivog teksta u value
    // "S učenikom" → "s_ucenikom"
    let userCategoryValue = '';
    const categoryMap = {
      'S učenikom': 's_ucenikom',
      'S roditeljima': 's_roditeljima',
      'S nastavnikom': 's_nastavnikom',
      'S nastavnicima': 's_nastavnicima',
      'S učiteljem': 's_uciteljem',
      'S učiteljima': 's_uciteljima',
      'S stručnom službom': 's_strucnom_sluzbom'
    };
    userCategoryValue = categoryMap[userCategory] || '';
    
    document.getElementById('edit-userCategory').value = userCategoryValue;
    document.getElementById('edit-userCategory').disabled = false;
    document.getElementById('edit-userCategory').required = true;
    
    // Parsiraj note polje da izvučemo environment, initials i dodatno
    const noteText = session.note || '';
    const noteParts = noteText.split(' | ');
    
    let environment = '';
    let initials = '';
    let additionalNote = '';
    
    if (noteParts.length > 0) {
      // Prvi dio može biti environment
      const firstPart = noteParts[0].trim();
      if (firstPart === 'individualno' || firstPart === 'u grupi') {
        environment = firstPart;
        
        // Drugi dio mogu biti inicijali
        if (noteParts.length > 1) {
          const secondPart = noteParts[1].trim();
          if (secondPart.includes('.') && secondPart.length <= 5) {
            initials = secondPart;
            
            // Treći dio je dodatna napomena
            if (noteParts.length > 2) {
              additionalNote = noteParts.slice(2).join(' | ');
            }
          } else {
            // Drugi dio je dodatna napomena
            additionalNote = noteParts.slice(1).join(' | ');
          }
        }
      } else {
        // Cijeli note je dodatna napomena
        additionalNote = noteText;
      }
    }
    
    document.getElementById('edit-environment').value = environment;
    document.getElementById('edit-environment').disabled = false;
    document.getElementById('edit-environment').required = true;
    
    document.getElementById('edit-initials').value = initials;
    document.getElementById('edit-initials').disabled = false;
    
    document.getElementById('edit-note').value = additionalNote;
    
    // Postavi opacity
    document.getElementById('edit-userCategoryGroup').style.opacity = '1';
    document.getElementById('edit-environmentGroup').style.opacity = '1';
    document.getElementById('edit-initialsGroup').style.opacity = '1';
  }
  
  // Setup event listeners za radio buttons u modalu
  setupEditModalRadioHandlers();
  
  // Prikaži modal
  document.getElementById('editModal').classList.add('show');
}

function closeEditModal() {
  document.getElementById('editModal').classList.remove('show');
  document.getElementById('editForm').reset();
  currentEditingRecord = null;
  
  // 🔄 Resetuj dugme na originalni tekst i stanje
  const saveBtn = document.getElementById('saveEdit');
  if (saveBtn) {
    saveBtn.disabled = false;
    saveBtn.textContent = '💾 Sačuvaj promjene';
    saveBtn.style.opacity = '1';
    saveBtn.style.cursor = 'pointer';
  }
}

async function handleEditSubmit(e) {
  e.preventDefault();

  const id = document.getElementById('edit-id').value;
  
  // Provjeri koji tip aktivnosti je izabran
  const activityType = document.querySelector('input[name="edit-activityType"]:checked')?.value;
  
  let userCategory = '';
  let workType = '';
  let noteText = '';
  
  if (activityType === 'attendance') {
    // PRISUSTVOVANJE
    const attendanceType = document.getElementById('edit-attendanceType')?.value;
    
    userCategory = ''; // Prazan za prisustvovanje
    
    const attendanceLabels = {
      'odjeljenskom_vijecu': 'Odjeljenskom vijeću škole',
      'nastavnickom_vijecu': 'Nastavničkom vijeću škole',
      'multisektorskom_sastanku': 'Multisektorskom sastanku'
    };
    
    workType = attendanceType ? `Prisustvovanje - ${attendanceLabels[attendanceType]}` : 'Prisustvovanje';
    noteText = ''; // Prazan za prisustvovanje
    
  } else if (activityType === 'contact') {
    // KONTAKT RAD
    const contactType = document.getElementById('edit-contactType')?.value;
    const userCategoryValue = document.getElementById('edit-userCategory')?.value;
    const environment = document.getElementById('edit-environment')?.value;
    const initials = document.getElementById('edit-initials')?.value?.trim();
    const additionalNote = document.getElementById('edit-note')?.value?.trim();
    
    // Mapiraj userCategory u čitljiv tekst
    const userCategoryLabels = {
      's_ucenikom': 'S učenikom',
      's_roditeljima': 'S roditeljima',
      's_nastavnikom': 'S nastavnikom',
      's_nastavnicima': 'S nastavnicima',
      's_uciteljem': 'S učiteljem',
      's_uciteljima': 'S učiteljima',
      's_strucnom_sluzbom': 'S stručnom službom'
    };
    
    userCategory = userCategoryLabels[userCategoryValue] || userCategoryValue;
    
    // Mapiraj contactType u čitljiv tekst
    const contactLabels = {
      'direktni': 'Direktni kontakt rad',
      'online': 'Online kontakt rad'
    };
    
    workType = contactLabels[contactType] || 'Kontakt rad';
    
    // Formatiraj note: "environment | initials | additionalNote"
    const noteParts = [];
    if (environment) noteParts.push(environment);
    if (initials) noteParts.push(initials);
    if (additionalNote) noteParts.push(additionalNote);
    noteText = noteParts.join(' | ');
  }
  
  const updatedData = {
    id: id,
    activityDate: document.getElementById('edit-activityDate').value,
    school: document.getElementById('edit-school').value,
    userCategory: userCategory,
    workType: workType,
    minutes: parseInt(document.getElementById('edit-minutes').value, 10),
    note: noteText
  };

  // Validacija - prosljeđujemo 'edit' context
  const errors = validateData(updatedData, 'edit');
  if (Object.keys(errors).length > 0) {
    alert('Molimo ispravite greške u formi:\n' + Object.values(errors).join('\n'));
    return;
  }

  // 🔄 LOADING STATE - Disable dugme
  const saveBtn = document.getElementById('saveEdit');
  const originalText = saveBtn.textContent;
  saveBtn.disabled = true;
  saveBtn.textContent = '⏳ Spašavam promjene...';
  saveBtn.style.opacity = '0.6';
  saveBtn.style.cursor = 'not-allowed';

  try {
    const headers = {
      'Content-Type': 'application/json'
    };

    if (REQUIRE_AUTH && accessToken) {
      headers['Authorization'] = 'Bearer ' + accessToken;
    }

    const response = await fetch(N8N_UPDATE_URL, {
      method: 'PUT',
      headers: headers,
      body: JSON.stringify(updatedData)
    });

    if (!response.ok) {
      throw new Error('Greška pri ažuriranju: ' + response.status);
    }

    // 🔥 INVALIDATE CACHE
    historyCache = {};
    if (CACHE_CONFIG.enabled) {
      localStorage.removeItem(CACHE_CONFIG.storageKey);
    }

    // Zatvori modal
    closeEditModal();

    // Refresh trenutnog aktivnog tab-a
    const activeTab = document.querySelector('.history-tab.active');
    
    if (activeTab) {
      const tabId = activeTab.id;
      
      if (tabId === 'tab-today') {
        await loadHistoryTab('today');
      } else if (tabId === 'tab-current-month') {
        await loadHistoryTab('current_month');
      } else if (tabId === 'tab-previous-month') {
        await loadHistoryTab('previous_month');
      }
    }

    // ✅ NEMA ALERT - modal se samo zatvori

  } catch (error) {
    console.error('Greška:', error);
    alert('Greška pri ažuriranju: ' + error.message);
    
    // Re-enable dugme ako dođe do greške
    saveBtn.disabled = false;
    saveBtn.textContent = originalText;
    saveBtn.style.opacity = '1';
    saveBtn.style.cursor = 'pointer';
  }
}

// Globalne funkcije za onclick atribute (moraju biti dostupne u window scope)
window.editRecord = editRecord;
window.deleteRecord = deleteRecord;

// ===== LOGOUT =====

function setupLogoutHandler() {
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', handleLogout);
  }
}

function handleLogout() {
  if (confirm('Da li ste sigurni da želite da se odjavite?')) {
    // Očisti tokene
    localStorage.removeItem('access_token');
    localStorage.removeItem('id_token');
    localStorage.removeItem('refresh_token');
    
    // NE brišemo sessionStorage - može sadržati važne podatke
    
    // 🧹 Očisti URL parametre (ukloni ?code, ?error)
    // Ali RELOAD umjesto redirect (da sačuvamo session state)
    if (window.location.search) {
      // Ima URL parametre - očisti ih
      const cleanUrl = window.location.origin + window.location.pathname;
      window.location.replace(cleanUrl);
    } else {
      // Nema URL parametara - samo reload
      window.location.reload();
    }
  }
}