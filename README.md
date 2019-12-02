# EZRandom-JS
Provides easy-to-use functions to generate secure-random strings in Javascript

Uses [window.crypto if available (all modern browsers)](https://caniuse.com/#feat=cryptography) or falls back to a custom [ISAAC CSPRNG](http://rosettacode.org/wiki/The_ISAAC_Cipher) if it’s not available.

# Example Usage
```
 console.log("Random string: " + randomString(16));
 console.log("Random password: " + randomPassword(16));
 console.log("Random letters: " + randomAlpha(16));
 console.log("Random lowercase: " + randomAlphaLower(16));
 ```
