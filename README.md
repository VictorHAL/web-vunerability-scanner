# 🔍 Web Vulnerability Scanner

Scanner de vulnerabilidades na camada de aplicação web.

**Disciplina:** Segurança Cibernética — UNIFOR  
**Integrantes:** Victor Hansi, Gil Melo, Marcos Antonio Félix  
**Framework:** CyBOK — Web & Mobile Security

---

## 🚀 Como rodar

### Com Docker (recomendado)

```bash
docker-compose up --build
```

A API estará disponível em: `http://localhost:8000`  
Documentação interativa: `http://localhost:8000/docs`

---

### Sem Docker

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

---

## 📡 Uso da API

### Escanear uma URL

**POST** `/api/v1/scan`

```json
{
  "url": "https://exemplo.com.br"
}
```

**Resposta:**

```json
{
  "url": "https://exemplo.com.br",
  "score": 65,
  "total_checks": 10,
  "passou": 5,
  "falhou": 5,
  "checks": [
    {
      "item": "Protocolo HTTPS",
      "descricao": "A aplicação utiliza HTTPS...",
      "status": "OK",
      "risco": null,
      "recomendacao": null
    },
    {
      "item": "Content-Security-Policy (CSP)",
      "descricao": "Previne ataques XSS...",
      "status": "FALHOU",
      "risco": "ALTO",
      "recomendacao": "Adicione o header Content-Security-Policy..."
    }
  ]
}
```

---

## ✅ Verificações realizadas

| Verificação | Risco se ausente |
|---|---|
| Protocolo HTTPS | ALTO |
| Content-Security-Policy | ALTO |
| Strict-Transport-Security (HSTS) | ALTO |
| X-Frame-Options | MÉDIO |
| X-Content-Type-Options | MÉDIO |
| Referrer-Policy | BAIXO |
| Permissions-Policy | BAIXO |
| Server header exposto | BAIXO |
| X-Powered-By exposto | BAIXO |
| Cookies: HttpOnly | ALTO |
| Cookies: Secure | ALTO |
| Cookies: SameSite | MÉDIO |

---

## 🏗️ Estrutura do projeto

```
web-vulnerability-scanner/
├── backend/
│   ├── main.py              # Entry point FastAPI
│   ├── schemas.py           # Modelos Pydantic
│   ├── routers/
│   │   └── scanner.py       # Endpoint POST /scan
│   ├── scanner/
│   │   ├── headers.py       # Verificação de headers HTTP
│   │   ├── cookies.py       # Verificação de cookies
│   │   ├── https_check.py   # Verificação de HTTPS
│   │   └── score.py         # Cálculo do score de segurança
│   ├── tests/
│   │   └── test_scanner.py  # Testes automatizados
│   ├── requirements.txt
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 🛡️ Segurança da própria ferramenta

- **Prevenção de SSRF:** URLs internas (localhost, 192.168.x.x) são bloqueadas
- **Timeout:** Requisições limitadas a 10 segundos
- **CORS:** Configurável para restringir origens em produção
