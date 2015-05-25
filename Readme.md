# The 'users' Packages

[![Build Status](https://travis-ci.org/agrafix/users.svg)](https://travis-ci.org/agrafix/users)

A set of libraries simplifying user management for web applications. 

Hackage: [users](http://hackage.haskell.org/package/users)

## Why?
When building a prototype, a small or medium sized Haskell web application with some type of user management, one has to reimplement that management for every project. This is tiring and error prone, thus the users package. It provides a simple API to user management, exchangable backends and a [test specification](http://hackage.haskell.org/package/users-test) for backends.

## Features

* Simple API
* CRUD for users
* Session management
* Password resetting
* Activation of users

## Backends

* [postgresql-simple](http://hackage.haskell.org/package/users-postgresql-simple)
* [persistent](http://hackage.haskell.org/package/users-persistent)

## Contribution

Feel free to extend the test specification with anything you want to have tested and submit a pull request. Backends can be either provided as pull request if they are 'mainstream' enough or you can create a separate repository and have it linked here. The major versions of all backend packages should match the major version of the core package providing the `UserStorageBackend` typeclass.
