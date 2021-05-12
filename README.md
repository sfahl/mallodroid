mallodroid
==========
# Crucial Changes
This forked version is a python3 converted mallodroid version.

This version this version adds **internal APIs** and **save output (XML) to a file** with `-o output file`.

You **must** have python3 in order to proceed.

Check the fork-source for the original author.

This repo include the https://github.com/luckenzo/mallodroid AndroGuard Changes.

## What it does
Find broken SSL certificate validation in Android Apps. MalloDroid is a small tool built on top of the [androguard](https://github.com/androguard/androguard) reverse engineering framework for Android applications. Hence, androguard is required to use MalloDroid.

===============================

### Usage
Example: ./mallodroid.py -f ExampleApp.apk -x

./mallodroid.py --help

===============================

#### Internal API

You can now import mallodroid with `import mallodroid` and execute it with `mallodroid.main(*args)`. 

`*args` should have:

* `args=['-args','--like','a','bash','call']`,

  *Demonstrative example:*

  `mallodroid.main(args=['-f','ExampleApp.apk','-x'])`

* `stdout_suppress=False`,

  Suppress all output sent to `STDOUT`. Default to `False`.

  *Demonstrative example:*

  `mallodroid.main(args=['-f','ExampleApp.apk','-x'],stdout_suppress=True)`

* `stderr_suppress=False`

  Suppress all output (errors) sent to `STDERR`. Default to `False`.

  *Demonstrative example:*

  `mallodroid.main(args=['-f','ExampleApp.apk','-x'],stderr_suppress=True)`

Complete example:

```python
import mallodroid

raw_results = mallodroid.main(args=['-f','ExampleApp.apk','-x'],stdout_suppress=False,stderr_suppress=True)

print(raw_results)
```



### Contact
Please do not hesitate to contact me if you have comments or questions.