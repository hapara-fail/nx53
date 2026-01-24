# Contributing Guidelines

First off, thank you for considering contributing to **nx53**. This project acts as a critical line of defense for open DNS resolvers, and your help is vital to keeping it performant, secure, and reliable.

Whether you are fixing a logic bug, optimizing the packet inspection engine, or implementing a new mode, we welcome your contributions.

## 🐛 Reporting Issues

We have simplified our issue reporting process. Please use the direct links below to **open an issue** using the correct template.

### 1. Reporting Bugs

If the daemon crashes, panics, or misidentifies traffic:

- **[Click here to open a Bug Report](https://github.com/hapara-fail/nx53/issues/new?template=bug_report.yml)**
- **Crucial:** Please provide your OS, Kernel version, and the specific command/flags used when the error occurred.

### 2. Suggesting Features & Improvements

If you have an idea for a new heuristic algorithm or optimization:

- **[Click here to open a Feature Request](https://github.com/hapara-fail/nx53/issues/new?template=feature_request.yml)**
- We love community ideas! If you have technical insights on how to implement your idea in Rust, please include them.

---

## 🛠️ Submitting Changes (Pull Requests)

We welcome direct code contributions. Please follow these guidelines to ensure your Pull Request (PR) is accepted.

### 1. Project Structure

The project is built in **Rust**.

- **`src/logic.rs`**: Core heuristic engine and state management.
- **`src/cli.rs`**: Command-line argument parsing (Clap).
- **`src/main.rs`**: Entry point and packet capture loop.
- **`Cargo.toml`**: Dependencies.

### 2. How to Contribute

1.  **Fork** the repository to your own GitHub account.
2.  **Create a Branch** for your specific change (e.g., `fix-pcap-overflow` or `add-json-logging`).
3.  **Make your changes.**
4.  **Test Locally:**
    - Run `cargo test` to ensure all unit tests pass.
    - Run `cargo clippy` to check for lints and best practices.
    - Build with `cargo build --release` to verify compilation.
5.  **Commit** your changes with a clear message:
    - _Good:_ "Fix memory leak in HashMap cleanup"
    - _Bad:_ "update code"
6.  **Push** to your branch and open a **Pull Request**.

### 3. Style Guidelines

- **Code:** Follow standard Rust formatting (`cargo fmt`). Use idiomatic Rust patterns.
- **Performance:** This is a high-throughput application. Avoid unnecessary clones or allocations in the hot path (packet loop).
- **Safety:** Minimize `unsafe` blocks unless absolutely necessary for FFI or performance (with justification).

---

## 🤝 Code of Conduct

We value accuracy, privacy, and collaboration. Please ensure your interactions—whether in issues, pull requests, or Discord—are respectful and constructive. By participating, you are expected to uphold our **[Code of Conduct](https://github.com/hapara-fail/nx53/blob/main/CODE_OF_CONDUCT.md)**.

## 📜 License

By contributing to hapara.fail, you agree that your contributions will be licensed under the same **GNU General Public License v3.0 (GPLv3)** that covers the project. Details can be found at [www.hapara.fail/license](https://www.hapara.fail/license).
