// Simple encryption and decryption functions
function encrypt(text) {
    return btoa(text); // Base64 encoding
}

function decrypt(encryptedText) {
    return atob(encryptedText); // Base64 decoding
}

function encryptPassword() {
    var passwordInput = document.getElementById("password").value;
    var encryptedPassword = encrypt(passwordInput);
    document.getElementById("encryptedPassword").innerHTML = "Encrypted Password: " + encryptedPassword;
}

function decryptPassword() {
    var encryptedPassword = document.getElementById("encryptedPassword").innerHTML.split(": ")[1];
    var decryptedPassword = decrypt(encryptedPassword);
    document.getElementById("decryptedPassword").innerHTML = "Decrypted Password: " + decryptedPassword;
}
