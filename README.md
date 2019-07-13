# Instructoins

## Compile

```
$ GOOS=js GOARCH=wasm go build -o main.wasm
```

## Serve

I like browsersync.

```
$ go get github.com/schollz/browsersync
$ browsersync
```

Open up `localhost:8002` and in the console, you can try things like:

## Generating a PAKE session key

```
bob = pakeInit("pass1","0");
jane = pakeInit("pass1","1");
jane = pakeUpdate(jane,pakePublic(bob));
bob = pakeUpdate(bob,pakePublic(jane));
jane = pakeUpdate(jane,pakePublic(bob));
console.log(pakeSessionKey(bob))
console.log(pakeSessionKey(jane))
```

## Encrypt/Decrypt

```
> enc = encrypt("hello, world","password","salt");
> console.log(decrypt(enc,"password","salt"))
hello, world
```