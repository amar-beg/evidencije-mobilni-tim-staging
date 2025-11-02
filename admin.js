// ===== KONFIGURACIJA =====
const COGNITO_DOMAIN = 'us-east-1vfdixxwye.auth.us-east-1.amazoncognito.com';
const N8N_CREATE_USER_URL = 'https://amar.prodesign387.com/webhook/create-user';

// Globalne reference
let idToken = null;
let currentUserEmail = null;

// ===== HELPER FUNKCIJE =====

// Generiši random password u formatu TempPass{XX}
function generateTempPassword() {
  const randomNum = Math.floor(Math.random() * 90) + 10; // Random broj 10-99
  return `TempPass${randomNum}`;
}

// ===== INICIJALIZACIJA =====
window.onload = function() {
  // Provjeri autentifikaciju - koristi ID token!
  idToken = localStorage.getItem('id_token');
  
  if (!idToken) {
    alert('Morate biti prijavljeni.');
    window.location.href = 'app.html';
    return;
  }

  // Provjeri admin role
  const decoded = parseJWT(idToken);
  const userRole = decoded['custom:role'];
  currentUserEmail = decoded.email;

  console.log('===== ADMIN PANEL DEBUG =====');
  console.log('Using ID token');
  console.log('Current user:', currentUserEmail);
  console.log('Role value:', userRole);
  console.log('===========================');

  if (userRole !== 'admin') {
    console.error('⛔ ACCESS DENIED - User role is not admin!');
    alert('⛔ Nemate pristup admin panelu!\n\nVaša uloga: ' + (userRole || 'nije postavljena'));
    window.location.href = 'app.html';
    return;
  }

  console.log('✅ Admin access granted!');
  // Admin verified - inicijalizuj panel
  initAdminPanel();
};

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

// Inicijalizacija admin panela
function initAdminPanel() {
  console.log('Initializing admin panel...');
  
  // Setup form handler
  const form = document.getElementById('addUserForm');
  form.addEventListener('submit', handleAddUser);
}

// Handle dodavanje korisnika
async function handleAddUser(e) {
  e.preventDefault();
  
  clearErrors();
  hideMessage();
  hideCreatedCard();

  // Prikupi podatke
  const firstName = document.getElementById('userFirstName').value.trim();
  const lastName = document.getElementById('userLastName').value.trim();
  const email = document.getElementById('userEmail').value.trim();
  const position = document.getElementById('userPosition').value;
  const homeSchool = document.getElementById('userHomeSchool').value;
  const role = document.getElementById('userRole').value;

  // Validacija
  if (!firstName) {
    showError('userFirstName', 'Ime je obavezno.');
    return;
  }

  if (!lastName) {
    showError('userLastName', 'Prezime je obavezno.');
    return;
  }

  if (!email) {
    showError('userEmail', 'Email je obavezan.');
    return;
  }

  if (!validateEmail(email)) {
    showError('userEmail', 'Unesite validan email.');
    return;
  }

  if (!position) {
    showError('userPosition', 'Pozicija je obavezna.');
    return;
  }

  if (!homeSchool) {
    showError('userHomeSchool', 'Matična škola je obavezna.');
    return;
  }

  // Kreiraj korisnika
  await createUser(firstName, lastName, email, position, homeSchool, role);
}

// Kreiraj korisnika preko n8n
async function createUser(firstName, lastName, email, position, homeSchool, role) {
  setLoading(true);

  try {
    // Generiši temp password
    const tempPassword = generateTempPassword();
    console.log('Generated temp password:', tempPassword);
    
    const payload = {
      firstName: firstName,
      lastName: lastName,
      email: email,
      tempPassword: tempPassword,  // ✅ Dodajemo generirani password
      position: position,
      homeSchool: homeSchool,
      role: role,
      adminEmail: currentUserEmail
    };

    console.log('===== CREATE USER =====');
    console.log('Payload:', payload);
    console.log('URL:', N8N_CREATE_USER_URL);

    const response = await fetch(N8N_CREATE_USER_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + idToken  // ← Šalji ID token!
      },
      body: JSON.stringify(payload)
    });

    console.log('Response status:', response.status);
    console.log('Response ok:', response.ok);

    if (!response.ok) {
      const errorData = await response.text();
      console.error('Error response:', errorData);
      throw new Error('Greška pri kreiranju korisnika: ' + response.status);
    }

    const data = await response.json();
    console.log('User created:', data);
    console.log('======================');

    // Prikaži uspješnu poruku
    showMessage('Korisnik je uspješno kreiran! ✅', 'success');

    // Prikaži kreiranje podatke - koristi password iz payloada
    displayCreatedUser(firstName, lastName, email, tempPassword, position, homeSchool);

    // Resetuj formu
    document.getElementById('addUserForm').reset();

  } catch (error) {
    console.error('Create user error:', error);
    showMessage('Greška: ' + error.message, 'error');
  } finally {
    setLoading(false);
  }
}

// Prikaz kreiranih podataka
function displayCreatedUser(firstName, lastName, email, password, position, school) {
  document.getElementById('createdFullName').textContent = firstName + ' ' + lastName;
  document.getElementById('createdEmail').textContent = email;
  document.getElementById('createdPassword').textContent = password;
  document.getElementById('createdPosition').textContent = position;
  document.getElementById('createdSchool').textContent = school;
  document.getElementById('userCreatedCard').style.display = 'block';

  // Scroll do kartice
  document.getElementById('userCreatedCard').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Sakrij karticu sa podacima
function hideCreatedCard() {
  document.getElementById('userCreatedCard').style.display = 'none';
}

// Kopiraj kredencijale
function copyCredentials() {
  const fullName = document.getElementById('createdFullName').textContent;
  const email = document.getElementById('createdEmail').textContent;
  const password = document.getElementById('createdPassword').textContent;
  const position = document.getElementById('createdPosition').textContent;
  const school = document.getElementById('createdSchool').textContent;

  const text = `
Pristup aplikaciji - Evidencija rada Mobilnog tima

Ime i prezime: ${fullName}
Email: ${email}
Privremeni password: ${password}
Pozicija: ${position}
Matična škola: ${school}

Molimo prijavite se na: http://mobilni-tim.evidencije.com
Pri prvom logovanju morate promijeniti password.
  `.trim();

  navigator.clipboard.writeText(text).then(() => {
    showMessage('📋 Podaci kopirani u clipboard!', 'success');
  }).catch(err => {
    console.error('Copy failed:', err);
    alert('Greška pri kopiranju. Molimo kopirajte ručno.');
  });
}

// Kopiraj samo password
function copyPasswordOnly() {
  const password = document.getElementById('createdPassword').textContent;
  
  navigator.clipboard.writeText(password).then(() => {
    showMessage('📋 Password kopiran u clipboard!', 'success');
  }).catch(err => {
    console.error('Copy failed:', err);
    alert('Greška pri kopiranju. Molimo kopirajte ručno.');
  });
}

// Validacija email-a
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

// UI helper funkcije
function setLoading(isLoading) {
  const btn = document.getElementById('addUserBtn');
  if (isLoading) {
    btn.disabled = true;
    btn.textContent = 'Kreiram korisnika...';
  } else {
    btn.disabled = false;
    btn.textContent = 'Dodaj korisnika';
  }
}

function showError(fieldId, message) {
  const errorEl = document.getElementById('error-' + fieldId);
  if (errorEl) {
    errorEl.textContent = message;
    errorEl.classList.add('show');
  }
}

function clearErrors() {
  const errorElements = document.querySelectorAll('.field-error');
  errorElements.forEach(el => {
    el.textContent = '';
    el.classList.remove('show');
  });
}

function showMessage(message, type) {
  const messageEl = document.getElementById('adminMessage');
  messageEl.textContent = message;
  messageEl.className = 'result-message show ' + type;

  // Auto hide nakon 5 sekundi
  setTimeout(() => {
    hideMessage();
  }, 5000);
}

function hideMessage() {
  const messageEl = document.getElementById('adminMessage');
  messageEl.className = 'result-message';
  messageEl.textContent = '';
}

// Logout funkcija
function logout() {
  if (confirm('Da li ste sigurni da želite da se odjavite?')) {
    localStorage.removeItem('access_token');
    localStorage.removeItem('id_token');
    localStorage.removeItem('refresh_token');
    window.location.href = 'app.html';
  }
}