---
title: Frida
published: 2024-12-03
description: ''
image: ''
tags: [Android, Frida, Reverse Engineering]
category: 'Note'
draft: false 
lang: ''
---

My notes for using Frida

# Android

Write script to a .js file. Usage:
```
frida -U com.example.app -l script.js
```

## Common information

### Check Java available
```js
console.log(Java.available)
```

### Check Android Version
```js
console.log(Java.androidVersion)
```

## List classes
```js
Java.perform(() => {
  console.log("List classes in package com.example.app");
  Java.enumerateLoadedClasses({
    onMatch: function(className) {
      if (className.startsWith("com.example.app")) {
        console.log(className); 
      }
    },
    onComplete: function() {
      console.log("Done"); 
    }
  });
});
```
or, this version return a list:
```js
Java.perform(function () {
  const classes = Java.enumerateLoadedClassesSync();
  console.log("Num of classes: ", classes.length);
  // console.log("Loaded classes: ", classes);
  // classes.forEach(function (cls) {
  //   if (cls.includes("com.example.app"))
  //     console.log(cls);
  // });
});
```

## List methods of classes
Replace **\_\_class\_\_** and **\_\_method\_\_**, with globs permitted.
```js
Java.perform(() => {
  const groups = Java.enumerateMethods('*__class__*!__method__*')
  console.log(JSON.stringify(groups, null, 2));
});
```

## Call method
```js
Java.perform(() => {
  const targetedClass = Java.use("com.example.app");
  const instance = targetedClass.$new();
  const method = instance.__targetMethod__(var1, var2);
});
```

Nested call method
```js
Java.perform(() => {
  const Activity = Java.use('android.app.Activity');
  const Exception = Java.use('java.lang.Exception');
  Activity.__targetMethod__.implementation = function () {
    throw Exception.$new('Oh noes!');
  };
});
```

## Overwrite method
```js
Java.perform(() => {
  const targetedClass = Java.use("com.example.app");
  const instance = targetedClass.$new();
  console.log("Instance: ", instance);
  instance.__firstTargetMethod__.implementation = function () {
    console.log("__firstTargetMethod__() called");
    // Do something here
  }

  instance.__secondTargetMethod__.implementation = function () {
    console.log("__secondTargetMethod__() called");
    // Also do something with this one
  }
});
```
