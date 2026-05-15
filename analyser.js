// ============================================================
// Password Strength Analyser & Security Advisor
// All analysis runs locally in the browser — nothing leaves your machine.
// ============================================================

(() => {
    'use strict';

    // --- Common password patterns & dictionaries ---
    const COMMON_PASSWORDS = new Set([
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
        'dragon', '111111', 'baseball', 'iloveyou', 'trustno1', 'sunshine',
        'princess', 'football', 'charlie', 'shadow', 'michael', 'login',
        'letmein', 'superman', 'hello', 'welcome', 'admin', 'passw0rd',
        'password1', '123456789', '1234567890', '1234', '12345', '123123',
        'qwerty123', '1q2w3e4r', 'admin123', 'root', 'toor', 'pass',
        'test', 'guest', 'access', 'love', 'god', 'secret', 'sex', 'money'
    ]);

    const KEYBOARD_PATTERNS = [
        'qwerty', 'qwertz', 'azerty', 'asdf', 'zxcv', 'qazwsx',
        '1234', '2345', '3456', '4567', '5678', '6789', '7890',
        'qwer', 'wert', 'erty', 'rtyu', 'tyui', 'yuio', 'uiop',
        'asdf', 'sdfg', 'dfgh', 'fghj', 'ghjk', 'hjkl',
        'zxcv', 'xcvb', 'cvbn', 'vbnm'
    ];

    const LEET_MAP = { '4': 'a', '@': 'a', '3': 'e', '1': 'i', '!': 'i', '0': 'o', '5': 's', '$': 's', '7': 't', '+': 't' };

    // --- DOM Elements ---
    const passwordInput = document.getElementById('passwordInput');
    const toggleBtn = document.getElementById('toggleVisibility');
    const meterBar = document.getElementById('meterBar');
    const strengthLabel = document.getElementById('strengthLabel');
    const crackTime = document.getElementById('crackTime');
    const lengthStat = document.getElementById('lengthStat');
    const entropyStat = document.getElementById('entropyStat');
    const charsetStat = document.getElementById('charsetStat');
    const scoreStat = document.getElementById('scoreStat');
    const checksList = document.getElementById('checksList');
    const adviceList = document.getElementById('adviceList');
    const genLength = document.getElementById('genLength');
    const genLengthValue = document.getElementById('genLengthValue');
    const generateBtn = document.getElementById('generateBtn');
    const generatedPassword = document.getElementById('generatedPassword');

    // --- Toggle password visibility ---
    toggleBtn.addEventListener('click', () => {
        const isPassword = passwordInput.type === 'password';
        passwordInput.type = isPassword ? 'text' : 'password';
        toggleBtn.querySelector('.eye-icon').textContent = isPassword ? '🙈' : '👁️';
    });

    // --- Analyse on input ---
    passwordInput.addEventListener('input', () => {
        const password = passwordInput.value;
        if (!password) {
            resetUI();
            return;
        }
        const result = analysePassword(password);
        renderResult(result);
    });

    // --- Core analysis ---
    function analysePassword(password) {
        const length = password.length;
        const charset = getCharsetSize(password);
        const entropy = calculateEntropy(password, charset);
        const checks = runChecks(password);
        const score = calculateScore(password, entropy, checks);
        const strength = getStrengthLevel(score);
        const crackTimeEstimate = estimateCrackTime(entropy);
        const advice = generateAdvice(password, checks, score);

        return { length, charset, entropy, checks, score, strength, crackTimeEstimate, advice };
    }

    function getCharsetSize(password) {
        let size = 0;
        if (/[a-z]/.test(password)) size += 26;
        if (/[A-Z]/.test(password)) size += 26;
        if (/[0-9]/.test(password)) size += 10;
        if (/[^a-zA-Z0-9]/.test(password)) size += 33;
        return size;
    }

    function calculateEntropy(password, charset) {
        if (charset === 0 || password.length === 0) return 0;
        return Math.round(password.length * Math.log2(charset) * 10) / 10;
    }

    function calculateScore(password, entropy, checks) {
        let score = 0;

        // Base score from entropy (max 50)
        score += Math.min(50, entropy * 0.7);

        // Length bonus (max 20)
        score += Math.min(20, password.length * 1.5);

        // Diversity bonus (max 15)
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasDigit = /[0-9]/.test(password);
        const hasSymbol = /[^a-zA-Z0-9]/.test(password);
        const diversity = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
        score += diversity * 3.75;

        // Penalties
        const failedChecks = checks.filter(c => c.status === 'fail').length;
        const warnChecks = checks.filter(c => c.status === 'warn').length;
        score -= failedChecks * 12;
        score -= warnChecks * 5;

        return Math.max(0, Math.min(100, Math.round(score)));
    }

    function getStrengthLevel(score) {
        if (score >= 80) return { label: 'Very Strong', color: '#2ed573', level: 4 };
        if (score >= 60) return { label: 'Strong', color: '#7bed9f', level: 3 };
        if (score >= 40) return { label: 'Moderate', color: '#ffa502', level: 2 };
        if (score >= 20) return { label: 'Weak', color: '#ff6348', level: 1 };
        return { label: 'Very Weak', color: '#ff4757', level: 0 };
    }

    function estimateCrackTime(entropy) {
        // Assume 10 billion guesses/sec (modern GPU cluster)
        const guessesPerSec = 1e10;
        const combinations = Math.pow(2, entropy);
        const seconds = combinations / guessesPerSec / 2; // average case

        if (seconds < 0.001) return 'Instantly';
        if (seconds < 1) return 'Less than a second';
        if (seconds < 60) return `${Math.round(seconds)} seconds`;
        if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
        if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
        if (seconds < 31536000 * 1000) return `${Math.round(seconds / 31536000)} years`;
        if (seconds < 31536000 * 1e6) return `${Math.round(seconds / 31536000 / 1000)}k years`;
        if (seconds < 31536000 * 1e9) return `${Math.round(seconds / 31536000 / 1e6)} million years`;
        return 'Billions of years+';
    }

    // --- Security Checks ---
    function runChecks(password) {
        const checks = [];
        const lower = password.toLowerCase();

        // Length check
        if (password.length >= 16) {
            checks.push({ label: 'Length is 16+ characters', status: 'pass' });
        } else if (password.length >= 12) {
            checks.push({ label: 'Length is 12+ characters (good)', status: 'pass' });
        } else if (password.length >= 8) {
            checks.push({ label: 'Length is 8-11 characters (minimum)', status: 'warn' });
        } else {
            checks.push({ label: 'Too short (less than 8 characters)', status: 'fail' });
        }

        // Character diversity
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasDigit = /[0-9]/.test(password);
        const hasSymbol = /[^a-zA-Z0-9]/.test(password);
        const diversity = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;

        if (diversity === 4) {
            checks.push({ label: 'Uses all character types (upper, lower, digits, symbols)', status: 'pass' });
        } else if (diversity >= 3) {
            checks.push({ label: `Uses ${diversity}/4 character types`, status: 'warn' });
        } else {
            checks.push({ label: `Only uses ${diversity}/4 character types`, status: 'fail' });
        }

        // Common password check
        if (COMMON_PASSWORDS.has(lower)) {
            checks.push({ label: 'Found in common password list', status: 'fail' });
        } else {
            checks.push({ label: 'Not a commonly used password', status: 'pass' });
        }

        // Leet speak detection
        const deleet = lower.split('').map(c => LEET_MAP[c] || c).join('');
        if (deleet !== lower && COMMON_PASSWORDS.has(deleet)) {
            checks.push({ label: 'Common password with leet speak substitutions', status: 'fail' });
        }

        // Repeated characters
        if (/(.)\1{2,}/.test(password)) {
            checks.push({ label: 'Contains repeated characters (e.g. "aaa")', status: 'fail' });
        } else {
            checks.push({ label: 'No excessive character repetition', status: 'pass' });
        }

        // Sequential characters
        if (hasSequentialChars(password)) {
            checks.push({ label: 'Contains sequential characters (e.g. "abc", "123")', status: 'warn' });
        } else {
            checks.push({ label: 'No sequential character patterns', status: 'pass' });
        }

        // Keyboard patterns
        const foundPattern = KEYBOARD_PATTERNS.find(p => lower.includes(p));
        if (foundPattern) {
            checks.push({ label: `Contains keyboard pattern ("${foundPattern}")`, status: 'fail' });
        } else {
            checks.push({ label: 'No keyboard walk patterns detected', status: 'pass' });
        }

        // All same case
        if (password.length > 2 && /^[a-z]+$/.test(password)) {
            checks.push({ label: 'All lowercase letters only', status: 'fail' });
        } else if (password.length > 2 && /^[A-Z]+$/.test(password)) {
            checks.push({ label: 'All uppercase letters only', status: 'fail' });
        } else if (password.length > 2 && /^[0-9]+$/.test(password)) {
            checks.push({ label: 'Numbers only — very predictable', status: 'fail' });
        }

        // Date patterns
        if (/(?:19|20)\d{2}/.test(password) || /\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}/.test(password)) {
            checks.push({ label: 'May contain a date (easily guessable)', status: 'warn' });
        }

        return checks;
    }

    function hasSequentialChars(password) {
        const lower = password.toLowerCase();
        for (let i = 0; i < lower.length - 2; i++) {
            const c1 = lower.charCodeAt(i);
            const c2 = lower.charCodeAt(i + 1);
            const c3 = lower.charCodeAt(i + 2);
            if (c2 - c1 === 1 && c3 - c2 === 1) return true;
            if (c1 - c2 === 1 && c2 - c3 === 1) return true;
        }
        return false;
    }

    // --- Security Advice ---
    function generateAdvice(password, checks, score) {
        const advice = [];

        if (password.length < 12) {
            advice.push('Increase length to at least 12 characters — length is the single biggest factor in password strength.');
        }

        if (password.length < 16 && score < 80) {
            advice.push('Aim for 16+ characters. Consider using a passphrase like "correct-horse-battery-staple".');
        }

        const hasSymbol = /[^a-zA-Z0-9]/.test(password);
        if (!hasSymbol) {
            advice.push('Add special characters (!@#$%^&*) to expand the character set attackers must try.');
        }

        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        if (!hasUpper || !hasLower) {
            advice.push('Mix uppercase and lowercase letters throughout the password, not just at the start.');
        }

        if (checks.some(c => c.status === 'fail' && c.label.includes('common password'))) {
            advice.push('This password appears in breach databases. Attackers try these first — choose something unique.');
        }

        if (checks.some(c => c.status === 'fail' && c.label.includes('keyboard pattern'))) {
            advice.push('Keyboard patterns (qwerty, asdf) are among the first things attackers check. Avoid them.');
        }

        if (checks.some(c => c.label.includes('repeated characters'))) {
            advice.push('Avoid repeating the same character — it reduces effective entropy.');
        }

        if (checks.some(c => c.label.includes('date'))) {
            advice.push('Dates (birthdays, anniversaries) are easily guessed through social engineering. Avoid them.');
        }

        if (score >= 60) {
            advice.push('Use a password manager to store unique passwords for every account.');
            advice.push('Enable two-factor authentication (2FA) wherever possible for an extra layer of security.');
        }

        if (advice.length === 0) {
            advice.push('Excellent password! Store it in a password manager and enable 2FA for maximum security.');
        }

        return advice;
    }

    // --- Rendering ---
    function renderResult(result) {
        // Meter
        const percent = result.score;
        meterBar.style.width = `${percent}%`;
        meterBar.style.backgroundColor = result.strength.color;

        // Labels
        strengthLabel.textContent = result.strength.label;
        strengthLabel.style.color = result.strength.color;
        crackTime.textContent = `Estimated crack time: ${result.crackTimeEstimate}`;

        // Stats
        lengthStat.textContent = result.length;
        entropyStat.textContent = result.entropy;
        charsetStat.textContent = result.charset;
        scoreStat.textContent = result.score;

        // Checks
        checksList.innerHTML = result.checks.map(check => {
            const icon = check.status === 'pass' ? '✓' : check.status === 'warn' ? '⚠' : '✗';
            const cls = `check-${check.status}`;
            return `<div class="check-item">
                <span class="check-icon ${cls}">${icon}</span>
                <span>${check.label}</span>
            </div>`;
        }).join('');

        // Advice
        adviceList.innerHTML = result.advice.map(a => `<li>${a}</li>`).join('');
    }

    function resetUI() {
        meterBar.style.width = '0%';
        strengthLabel.textContent = 'Enter a password to analyse';
        strengthLabel.style.color = '';
        crackTime.textContent = '';
        lengthStat.textContent = '0';
        entropyStat.textContent = '0';
        charsetStat.textContent = '0';
        scoreStat.textContent = '0';
        checksList.innerHTML = '';
        adviceList.innerHTML = '';
    }

    // --- Password Generator ---
    genLength.addEventListener('input', () => {
        genLengthValue.textContent = genLength.value;
    });

    generateBtn.addEventListener('click', () => {
        const length = parseInt(genLength.value, 10);
        const useUpper = document.getElementById('genUpper').checked;
        const useLower = document.getElementById('genLower').checked;
        const useNumbers = document.getElementById('genNumbers').checked;
        const useSymbols = document.getElementById('genSymbols').checked;

        let chars = '';
        if (useLower) chars += 'abcdefghijklmnopqrstuvwxyz';
        if (useUpper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (useNumbers) chars += '0123456789';
        if (useSymbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';

        if (!chars) {
            generatedPassword.textContent = 'Select at least one character type.';
            generatedPassword.classList.add('visible');
            return;
        }

        const array = new Uint32Array(length);
        crypto.getRandomValues(array);
        let generated = '';
        for (let i = 0; i < length; i++) {
            generated += chars[array[i] % chars.length];
        }

        generatedPassword.textContent = generated;
        generatedPassword.classList.add('visible');

        // Auto-analyse the generated password
        passwordInput.value = generated;
        passwordInput.dispatchEvent(new Event('input'));
    });

    // Copy generated password on click
    generatedPassword.addEventListener('click', () => {
        const text = generatedPassword.textContent;
        if (text && navigator.clipboard) {
            navigator.clipboard.writeText(text).then(() => {
                const original = generatedPassword.textContent;
                generatedPassword.textContent = '✓ Copied to clipboard!';
                setTimeout(() => {
                    generatedPassword.textContent = original;
                }, 1500);
            });
        }
    });

    // Focus input on load
    passwordInput.focus();
})();
