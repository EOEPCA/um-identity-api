<!-- PROJECT SHIELDS -->
<!--
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
![Build][build-shield]

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/EOEPCA/um-identity-api">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

<h3 align="center">Identity API</h3>

  <p align="center">
    Flask application to enable a REST API server to manage Keycloak through Keycloak Admin API (https://www.keycloak.org/docs-api/21.0.1/rest-api/index.html) and Protection API (https://www.keycloak.org/docs/latest/authorization_services/index.html#_service_protection_api).
    <br />
    <a href="https://github.com/EOEPCA/um-identity-api"><strong>Explore the docs »</strong></a>
    <br />
    <a href="https://github.com/EOEPCA/um-identity-api">View Demo</a>
    ·
    <a href="https://github.com/EOEPCA/um-identity-api/issues">Report Bug</a>
    ·
    <a href="https://github.com/EOEPCA/um-identity-api/issues">Request Feature</a>
  </p>
</p>

## Table of Contents

- [Table of Contents](#table-of-contents)
- [About The Project](#about-the-project)
    - [Built With](#built-with)
- [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Testing](#testing)
- [Documentation](#documentation)
- [Usage](#usage)
    - [Running the template service](#running-the-template-service)
    - [Upgrading Gradle Wrapper](#upgrading-gradle-wrapper)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Acknowledgements](#acknowledgements)

<!-- ABOUT THE PROJECT -->

## About The Project

Flask application to enable a REST API server to manage Keycloak through Keycloak Admin API (https://www.keycloak.org/docs-api/21.0.1/rest-api/index.html) and Protection API (https://www.keycloak.org/docs/latest/authorization_services/index.html#_service_protection_api).

Includes three main paths:
- **Resources** - CRUD operations to manage resources
- **Policies** - CRUD operations to manage policies
- **Permissions** - CRUD operations to manage permissions

### Built With

- [Python](https://www.python.org//)
- [PyTest](https://docs.pytest.org)
- [YAML](https://yaml.org/)
- [Travis CI](https://travis-ci.com/)

<!-- GETTING STARTED -->

## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

This is an example of how to list things you need to use the software and how to install them.

- [Docker](https://www.docker.com/)
- [Python](https://www.python.org//)

### Installation

1. Get into EOEPCA's development environment

```sh
vagrant ssh
```

3. Clone the repo

```sh
git clone https://github.com/EOEPCA/um-identity-apigit
```

4. Change local directory

```sh
cd um-identity-api
```

5. Execute

    5.1 Run with Python
    ```sh
    pip install -r requirements.txt
    python src/main.py
    ```
    5.1 Run with Python
    ```sh
    docker build -f identity-api/Dockerfile . -t identity-api:latest
    docker run --rm -dp 5566:5566 --name identity-api identity-api:latest
    ```

## Documentation

The component documentation can be found at https://eoepca.github.io/um-identity-api/.

<!-- USAGE EXAMPLES -->

## Usage

Use this space to show useful examples of how a project can be used. Additional screenshots, code examples and demos work well in this space. You may also link to more resources.

_For more examples, please refer to the [Documentation](https://example.com)_

<!-- ROADMAP -->

## Roadmap

See the [open issues](https://github.com/EOEPCA/um-identity-api/issues) for a list of proposed features (and known issues).

<!-- CONTRIBUTING -->

## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- LICENSE -->

## License

Distributed under the Apache-2.0 License. See `LICENSE` for more information.

## Contact

[EOEPCA mailbox](eoepca.systemteam@telespazio.com)

Project Link: [https://github.com/EOEPCA/um-identity-api](https://github.com/EOEPCA/um-identity-api)

## Acknowledgements

- README.md is based on [this template](https://github.com/othneildrew/Best-README-Template) by [Othneil Drew](https://github.com/othneildrew).


[contributors-shield]: https://img.shields.io/github/contributors/EOEPCA/um-identity-apisvg?style=flat-square
[contributors-url]: https://github.com/EOEPCA/um-identity-api/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/EOEPCA/um-identity-apisvg?style=flat-square
[forks-url]: https://github.com/EOEPCA/um-identity-api/network/members
[stars-shield]: https://img.shields.io/github/stars/EOEPCA/um-identity-apisvg?style=flat-square
[stars-url]: https://github.com/EOEPCA/um-identity-api/stargazers
[issues-shield]: https://img.shields.io/github/issues/EOEPCA/um-identity-apisvg?style=flat-square
[issues-url]: https://github.com/EOEPCA/um-identity-api/issues
[license-shield]: https://img.shields.io/github/license/EOEPCA/um-identity-apisvg?style=flat-square
[license-url]: https://github.com/EOEPCA/um-identity-api/blob/master/LICENSE
[build-shield]: https://www.travis-ci.com/EOEPCA/um-identity-apisvg?branch=master
