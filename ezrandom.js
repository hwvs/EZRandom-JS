/**
 * @name EZRandom Library
 * @file ezrandom.js
 * @license MIT License ( https://opensource.org/licenses/MIT )
 * @version 1.0.0
 * 
 * Provides easy-to-use functions to generate secure-random strings.
 * 
 * Uses window.crypto if available (all modern browsers) or falls back to a custom ISAAC
 * CSPRNG if it's not available.
 *
 * Includes ISAAC Cipher from ImagineProgramming (MIT License)
 *
 * Example Usage: console.log("Random string: " + randomString(16));
 * Example Usage: console.log("Random password: " + randomPassword(16));
 * Example Usage: console.log("Random letters: " + randomAlpha(16));
 * Example Usage: console.log("Random lowercase: " + randomAlphaLower(16));
 */


/**********************/
// START OF ISAAC CODE
/**********************/
/** 
  SmallPRNG's big brother!
  
  Not entirely finished, requires some testing, but ready for use.
  
  ISAAC library for JavaScript. Not special, 
  not optimized, not perfect. It produces
  cryptographic pseudo-random numbers by manipulating a context which was initialized 
  with or without a seed. 
  
  MIT licensed, use wherever you like, but a link
  back to my CodePen (ImagineProgramming) or website
  is appreciated (http://www.imagine-programming.com)
  
  Based on:
  http://burtleburtle.net/bob/rand/isaac.html
*/

(function(target, name) {
  if(!('Uint32Array' in window)) {
    Uint32Array = Array; // fine...
  }
  
  // maximum randval for .random([max/min [, max]])
  var RMAX = 0x7FFFFFFF;
  
  var floor = Math.floor,
      abs = Math.abs;

  var RANDSIZL = 8;
  var RANDSIZ  = (1 << RANDSIZL);

  var ISAACException = function(message) {
    this.name    = name+"Exception";
    this.message = message;
  };

  var ISAAC = function(seed) {
    this.cnt = 0;
    this.rsl = new Uint32Array(RANDSIZ);
    this.mem = new Uint32Array(RANDSIZ);
    this.a   = 0;
    this.b   = 0;
    this.c   = 0;

    // preseed the ctx if required.
    if(typeof(seed) !== "null" && typeof(seed) !== "undefined") {
      this.seed(seed);
    } else {
      this.init();
    }
  };

  var p = ISAAC.prototype;

  /**
    seed the cipher context with an array of numbers (of RANDSIZ size),
    an Uint32Array (of RANDSIZ size) or a number.
  */
  p.seed = function(seed) {
    var initFlag = false;
    // first try arrays
    if (Object.prototype.toString.call(seed) === '[object Array]') {
      for(var i = 0; i < RANDSIZ; i++) {
        this.rsl[i] = (seed[i] >>> 0) & 0xffffffff;
      }

      initFlag = true;
      // it might be a typed array
    } else if(typeof(seed) === "object" && seed instanceof Uint32Array) {
      for(var i = 0; i < RANDSIZ; i++) {
        this.rsl[i] = seed[i];
      }

      initFlag = true;
      // to hell with it, it's a number then?
    } else if (typeof(seed) === "number") {
      seed = (seed >>> 0) & 0xffffffff;
      for(var i = 0; i < RANDSIZ; i++) {
        this.rsl[i] = seed;
      }

      initFlag = true;
    } else {
      // not a valid type.
      throw new ISAACException("unknown seed type");
    }

    return this.init(initFlag);
  };

  /**
    step ciphers to the next set of pseudo-random integers.
  */
  p.step = function(times) {
    if(typeof(times) === "number") {
      for(var i = 0; i < times; i++) {
        this.step();
      }

      return;
    }

    var x, y;
    this.c++;
    this.b += this.c;

    for(var i = 0; i < RANDSIZ; ++i) {
      x = this.mem[i];
      switch(i % 4) {
        case 0: this.a = (this.a ^ (this.a << 13))>>>0; break;
        case 1: this.a = (this.a ^ (this.a >>  6))>>>0; break;
        case 2: this.a = (this.a ^ (this.a <<  2))>>>0; break;
        case 3: this.a = (this.a ^ (this.a >> 16))>>>0; break;
      }

      this.a = (this.mem[(i + 128) % RANDSIZ] + this.a)>>>0;
      this.mem[i] = y = (this.mem[(x >>> 2) % RANDSIZ] + this.a + this.b)>>>0;
      this.rsl[i] = this.b = (this.mem[(y >>> 10) % RANDSIZ] + x)>>>0;
    }
    
    this.cnt = (RANDSIZ - 1);
  };

  /**
    init initializes all the memory and values in the context and makes sure
    the first cipher step will be made. 
  */
  p.init = function(flag) {
    var a, b, c, d, e, f, g, h;   // ingredients for in our blender named mix()!
    this.a = this.b = this.c = 0; // clear a, b and c
    a=b=c=d=e=f=g=h = 0x9e3779b9; // the golden ratio

    // pfff - the blender! :)
    var mix = function() {
      a = (a ^ (b << 11)) >>> 0;
      d = (d + a) >>> 0;
      b = (b + c) >>> 0;
      b = (b ^ (c >> 2)) >>> 0;
      e = (e + b) >>> 0;
      c = (c + d) >>> 0;
      c = (c ^ (d << 8)) >>> 0;
      f = (f + c) >>> 0;
      d = (d + e) >>> 0;
      d = (d ^ (e >> 16)) >>> 0;
      g = (g + d) >>> 0;
      e = (e + f) >>> 0;
      e = (e ^ (f << 10)) >>> 0;
      h = (h + e) >>> 0;
      f = (f + g) >>> 0;
      f = (f ^ (g >> 4)) >>> 0;
      a = (a + f) >>> 0;
      g = (g + h) >>> 0;
      g = (g ^ (h << 8)) >>> 0;
      b = (b + g) >>> 0;
      h = (h + a) >>> 0;
      h = (h ^ (a >> 9)) >>> 0;
      c = (c + h) >>> 0;
      a = (a + b) >>> 0;
    };

    // scramble it
    for(var i = 0; i < 4; ++i) {
      mix();
    }

    if(flag) {
      // initialize using the contents of rsl[] as the seed
      for(var i = 0; i < RANDSIZ; i+=8) {
        a = (a + this.rsl[i  ]) >>> 0;
        b = (b + this.rsl[i+1]) >>> 0;
        c = (c + this.rsl[i+2]) >>> 0;
        d = (d + this.rsl[i+3]) >>> 0;
        e = (e + this.rsl[i+4]) >>> 0;
        f = (f + this.rsl[i+5]) >>> 0;
        g = (g + this.rsl[i+6]) >>> 0;
        h = (h + this.rsl[i+7]) >>> 0;

        mix();

        this.mem[i  ] = a;
        this.mem[i+1] = b;
        this.mem[i+2] = c;
        this.mem[i+3] = d;
        this.mem[i+4] = e;
        this.mem[i+5] = f;
        this.mem[i+6] = g;
        this.mem[i+7] = h;
      }

      // do a second pass to make all of the seed affect all of m
      for(var i = 0; i < RANDSIZ; i+=8) {
        a = (a + this.rsl[i  ]) >>> 0;
        b = (b + this.rsl[i+1]) >>> 0;
        c = (c + this.rsl[i+2]) >>> 0;
        d = (d + this.rsl[i+3]) >>> 0;
        e = (e + this.rsl[i+4]) >>> 0;
        f = (f + this.rsl[i+5]) >>> 0;
        g = (g + this.rsl[i+6]) >>> 0;
        h = (h + this.rsl[i+7]) >>> 0;

        mix();

        this.mem[i  ] = a;
        this.mem[i+1] = b;
        this.mem[i+2] = c;
        this.mem[i+3] = d;
        this.mem[i+4] = e;
        this.mem[i+5] = f;
        this.mem[i+6] = g;
        this.mem[i+7] = h;
      }
    } else {
      // fill in mem with messy stuff
      for(var i = 0; i < RANDSIZ; i+=8) {
        mix();

        this.mem[i  ] = a;
        this.mem[i+1] = b;
        this.mem[i+2] = c;
        this.mem[i+3] = d;
        this.mem[i+4] = e;
        this.mem[i+5] = f;
        this.mem[i+6] = g;
        this.mem[i+7] = h;
      }
    }

    this.step(); // fill in the first set of results
    this.cnt = RANDSIZ; // prepare to use the first set of results
  };

  /**
    pull the next 32-bit integer from the result array. If we run out of
    random data (this.cnt === 0): step the cipher for new data and reset
    the count.
  */
  p.long = function() {
    if(this.cnt-- === 0) {
      this.step();
      this.cnt = (RANDSIZ - 1); 
    }

    return this.rsl[this.cnt];
  };

  p.random = function() {
    var r = ((this.long() % RMAX) / RMAX);
    switch(arguments.length) {
        // zero arguments, return the 0-1 random factor
      case 0: {
        return r;
      } break;

        // 1 argument (max val), return random between 1 and max
      case 1: {
        var u = arguments[0];
        if(u < 1) {
          console.log("upper limit invalid");
          return null;
        }

        return (floor(r * u) + 1);

      } break;

        // 2 arguments (min, max val), return random between min and max
      case 2: {
        var l = arguments[0];
        var u = arguments[1];

        if(l >= u) {
          console.log("upper limit invalid");
          return null;
        }

        return (floor(r * (u - l + 1)) + l);
      } break;

      default: {
        console.log("invalid amount of arguments");
      } break;
    }

    return null;
  };

  target[name] = ISAAC;
  target[name+"Exception"] = ISAACException;
 
}(window, "ISAAC"));
/**********************/
// END OF ISAAC CODE
/**********************/


function singleRound() {
  var junk=0xffffff0f;
  var i=0;
  var start = new Date().getTime();

  while(new Date().getTime() == start) {
    i += 1;
    junk /= 3;
  }
 
  if(i == 0) {
    // this isn't good, the CPU is not fast enough. This shouldn't ever happen, but just in case, let's return at least something with some kind of entropy. Alternatively, throw an exception.
    return Math.floor((screen.left << 16) + (screen.top << 8) + (screen.width << 4) + (window.scrollY << 16) + (new Date()).getTime()  + (Math.random()*0xffffffff)) % 0xFFFFFFFF;
  } 
  return i;
}

function getRounds(count) {
  count = (typeof count !== 'undefined') ?  count : 256;
  var result = [];
  var baseLine = singleRound();
  for(var i=0;i<count;i++) {
    var a = Math.abs(singleRound() - baseLine) % 65536;
    var b = Math.abs(singleRound() - baseLine) % 65536;
    result.push((a<<16) | b);
  }
  
  return result;
}

function getISAACRandomness(count) {
	count = (typeof count !== 'undefined') ?  count : 16;
	var isaac = new ISAAC(getRounds());
	var result = [];

	for(var i=0;i<count;i++){ 
		result.push(isaac.long());
	}

	return result;
}


function getEntropy(length) {
  if (window.crypto.getRandomValues !== undefined) {
    var array = new Uint32Array(length);
    window.crypto.getRandomValues(array);
    return array;
  }
  else {
    return getISAACRandomness(length); //ISAAC PRNG fallback based on entropy collected from timing differences
  }
}


// Stuff you probably want to use below

function randomArray(length) {
  length = (typeof length !== 'undefined') ?  length : 16;
	return getEntropy(length);
}
function randomBytes(length) {
  length = (typeof length !== 'undefined') ?  length : 16;
 var result = [];
  var entropy = getEntropy(length);
  
  for(i=0;i<length;i++) {
    result.push(entropy[i] % 256);
  }
  
  return result;
}

function randomString(length, chars) {
  length = (typeof length !== 'undefined') ? length : 16;
  chars = (typeof chars !== 'undefined') ?  chars : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	
  var result = "";
  var entropy = getEntropy(length);
  
  for(i=0;i<length;i++) {
    result += chars[entropy[i] % chars.length];
  }
  
  return result;
}

function randomAlpha(length) {
  length = (typeof length !== 'undefined') ? length : 16;
  return randomString(length, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
}
function randomAlphaUpper(length) {
  length = (typeof length !== 'undefined') ? length : 16;
  return randomString(length, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
}
function randomAlphaLower(length) {
  length = (typeof length !== 'undefined') ? length : 16;
  return randomString(length, "abcdefghijklmnopqrstuvwxyz");
}
function randomDigits(length) {
  length = (typeof length !== 'undefined') ? length : 16;
  return randomString(length, "1234567890");
}
function randomPassword(length) {
  length = (typeof length !== 'undefined') ? length : 16;
  return randomString(length, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*-_=+?.");
}
