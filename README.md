[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
![Build][build-shield]

<br />
<p align="center">

<h3 align="center">Identity API</h3>

  <p align="center">
    FastAPI application exposing a Restful API to manage Keycloak through Keycloak Admin API (https://www.keycloak.org/docs-api/22.0.1/rest-api/index.html) and Protection API (https://www.keycloak.org/docs/latest/authorization_services/index.html#_service_protection_api).
    <br />
    <a href="https://github.com/EOEPCA/um-identity-api"><strong>Explore the docs »</strong></a>
    <br />
    ·
    <a href="https://github.com/EOEPCA/um-identity-api/issues">Report Bug</a>
    ·
    <a href="https://github.com/EOEPCA/um-identity-api/issues">Request Feature</a>
</p>

## Table of Contents

- [Table of Contents](#table-of-contents)
- [About The Project](#about-the-project)
    - [Built With](#built-with)
- [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
- [Documentation](#documentation)
- [Usage](#usage)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Acknowledgements](#acknowledgements)


## About The Project

FastAPI application exposing a Restful API to manage Keycloak through Keycloak Admin
API (https://www.keycloak.org/docs-api/21.0.1/rest-api/index.html) and Protection
API (https://www.keycloak.org/docs/latest/authorization_services/index.html#_service_protection_api).

Swagger docs are available at /docs.   
Redoc docs are available at /redoc.

### Built With

- [Python](https://www.python.org)
- [FastAPI](https://fastapi.tiangolo.com)

## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

- [Docker](https://www.docker.com)  
or
- [Docker compose](https://docs.docker.com/compose)  
or
- [Python](https://www.python.org)

### Installation

1. Clone the repo

```sh
git clone https://github.com/EOEPCA/um-identity-api
```

2. Change local directory

```sh
cd um-identity-api
```

3. Execute

   3.1 Run with docker compose (Identity API + Keycloak + Postgres)
    ```sh
    docker compose up -d --build
    ```
   3.2 Run with Python
    ```sh
    pip install -r requirements.txt
    uvicorn app.main:app
    ```
   3.3 Run with Docker
    ```sh
    docker build . --progress=plain -t um-identity-api:local
    docker run --rm -dp 8080:8080 --name um-identity-api um-identity-api:local
    ```
   3.4 Run develop branch with Docker
    ```sh
    docker run --rm -dp 8080:8080 --name um-identity-api ghcr.io/eoepca/um-identity-api:develop
    ```
   3.5 Run master branch with Docker
    ```sh
    docker run --rm -dp 8080:8080 --name um-identity-api ghcr.io/eoepca/um-identity-api:production
    ```

## Documentation

The component documentation can be found at https://eoepca.github.io/um-identity-api/.


## Usage

Check Redoc page to try out the API, available at http://localhost:8080/redoc

## Roadmap

See the [open issues](https://github.com/EOEPCA/um-identity-api/issues) for a list of proposed features (and known
issues).

## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any
contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request


## License

Distributed under the Apache-2.0 License. See `LICENSE` for more information.

## Contact

[EOEPCA mailbox](eoepca.systemteam@telespazio.com)

Project Link: [https://github.com/EOEPCA/um-identity-api](https://github.com/EOEPCA/um-identity-api)

## Acknowledgements

- README.md is based on [this template](https://github.com/othneildrew/Best-README-Template)
  by [Othneil Drew](https://github.com/othneildrew).

[contributors-shield]: https://img.shields.io/github/contributors/EOEPCA/um-identity-api.svg?style=flat-square

[contributors-url]: https://github.com/EOEPCA/um-identity-api/graphs/contributors

[forks-shield]: https://img.shields.io/github/forks/EOEPCA/um-identity-api.svg?style=flat-square

[forks-url]: https://github.com/EOEPCA/um-identity-api/network/members

[stars-shield]: https://img.shields.io/github/stars/EOEPCA/um-identity-api.svg?style=flat-square

[stars-url]: https://github.com/EOEPCA/um-identity-api/stargazers

[issues-shield]: https://img.shields.io/github/issues/EOEPCA/um-identity-api.svg?style=flat-square

[issues-url]: https://github.com/EOEPCA/um-identity-api/issues

[license-shield]: https://img.shields.io/github/license/EOEPCA/um-identity-api.svg?style=flat-square

[license-url]: https://github.com/EOEPCA/um-identity-api/blob/master/LICENSE

[build-shield]: https://www.travis-ci.com/EOEPCA/um-identity-api.svg?branch=master