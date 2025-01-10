# Digital Identity Mockup Service

© 2024 Hochschule für Wirtschaft und Technik Dresden. All rights reserved.

**Authors: Tom Bischopink**

Co-Authors: Nick Kemter, Matthias Kernke, Jessica Knick, Marvin Neidhardt, Toni Saupe

Supervisor: Jürgen Anke, Daniel Richter

## Setup for Development

Please install Python 3.9 or higher.

### Create Virtual Environment

```bash
python3.9 -m venv .venv
```

### Acitvate Virtual Environment

```bash
Source .venv/bin/activate
```

### Install requirements.txt

```bash
pip install -r requirements.txt
```

### Add .env variables

- create a **.env** file
- put the following credentials into the .env file

```bash
DATABASE_URL_PSQL=...
SECRET_KEY=...
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
PRIVATE_KEY_DIRECTORY=/My/App/...
```

### Start the FastAPI Service

```bash 
uvicorn app.main:app
```

Open the following URL: **http://127.0.0.1:8000**


### Run docker-compose up:
- create a **.env** file
- put the following credentials into the .env file

```bash
DATABASE_URL_PSQL=...
SECRET_KEY=...
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
PRIVATE_KEY_DIRECTORY=/My/App/...
```
### Run docker-compose up

```bash
docker-compose up
```
