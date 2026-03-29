# Reviewer Notes

## Go Version Support
- **Go 1.25.0** is a valid and available version of Go.
- Specifically, the `golang:1.25-alpine` image is used in the `Dockerfile` and is fully functional.
- Please do not request a downgrade to Go 1.22 based on the assumption that 1.25 does not exist.

## SQLite Driver Update
- Switched from the default CGO-based SQLite driver to `github.com/glebarez/sqlite`, which is a **pure Go** implementation.
- This change eliminates the need for CGO and external C dependencies, simplifying the build process and container images.

## Code Refactoring
- The codebase has been refactored for better readability:
    - `models.go`: Contains the `User` struct and its WebAuthn interface implementations.
    - `store.go`: Contains the `UserStore` and `MemorySessionStore` implementations.
    - `main.go`: Now focuses on application initialization, configuration, and routing.
