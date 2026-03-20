# HTB Lab — SQL Injection en panel de login (Apache/PHP)

> **Dificultad:** Muy fácil  
> **SO:** Linux (Debian)  
> **Servicio principal:** HTTP — Apache 2.4.38  
> **Técnica utilizada:** SQL Injection (bypass de autenticación)

---

## Índice

1. [Reconocimiento — escaneo de puertos](#1-reconocimiento--escaneo-de-puertos)
2. [Exploración web inicial](#2-exploración-web-inicial)
3. [Enumeración de directorios](#3-enumeración-de-directorios)
4. [Revisión de rutas encontradas](#4-revisión-de-rutas-encontradas)
5. [Análisis del código JavaScript](#5-análisis-del-código-javascript)
6. [Explotación — SQL Injection](#6-explotación--sql-injection)
7. [Flag obtenida](#7-flag-obtenida)
8. [Conclusiones y lecciones aprendidas](#8-conclusiones-y-lecciones-aprendidas)

---

## 1. Reconocimiento — escaneo de puertos

El primer paso en cualquier laboratorio es identificar qué servicios están corriendo en el objetivo. Para ello se utilizó `nmap` con detección de versiones y scripts por defecto:

```bash
nmap -sC -sV -Pn -p- --min-rate 5000 10.129.34.243
```

**Resultado:**

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-server-header: Apache/2.4.38 (Debian)
|_http-title: Login
```
<img width="690" height="279" alt="image" src="https://github.com/user-attachments/assets/f0e34c99-b1b8-44e5-a76f-bc1b1f7fa148" />


**Observaciones:**
- Solo hay un puerto abierto: el **80/TCP** con HTTP.
- El servidor es **Apache 2.4.38 sobre Debian**.
- El título de la página es `Login`, lo que indica directamente que hay un panel de autenticación.
- El servicio corre sobre HTTP plano (sin TLS), lo que significa que el tráfico no está cifrado.

---

## 2. Exploración web inicial

Al acceder a `http://10.129.34.243` en el navegador se presenta un **panel de login** con campos de usuario y contraseña.

<img width="787" height="717" alt="image" src="https://github.com/user-attachments/assets/b3b3a454-fbdf-492d-b2b4-8ec4f8231a6f" />

Detalles observados:
- La URL usa `http://` sin la `s`, confirmando la ausencia de cifrado.
- El navegador muestra el aviso **"Not Secure"**.
- El diseño incluye un campo `Username`, un campo `Password`, checkbox de "Remember me" y un enlace de "Forgot Password?".

Se revisó el **código fuente** de la página (`Ctrl+U`) sin encontrar credenciales, rutas ocultas ni comentarios relevantes.

---

## 3. Enumeración de directorios

Dado que el código fuente no reveló información útil, el siguiente paso fue enumerar rutas y archivos ocultos con `gobuster`:

```bash
gobuster dir -u http://10.129.34.243 \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html,txt
```

**Resultado:**

```
/images    (Status: 301) [→ http://10.129.34.243/images/]
/index.php (Status: 200) [Size: 4896]
/css       (Status: 301) [→ http://10.129.34.243/css/]
/js        (Status: 301) [→ http://10.129.34.243/js/]
/vendor    (Status: 301) [→ http://10.129.34.243/vendor/]
/fonts     (Status: 301) [→ http://10.129.34.243/fonts/]
```

<img width="699" height="432" alt="image" src="https://github.com/user-attachments/assets/0fd536e2-4dfd-4928-8348-21a12276d6d8" />


El único archivo con status `200` es `index.php` con un tamaño de 4896 bytes — el resto son redirecciones a directorios estáticos.

---

## 4. Revisión de rutas encontradas

Se accedió manualmente a cada directorio encontrado:

| Ruta | Contenido |
|------|-----------|
| `/images/` | Imágenes estáticas del diseño (sin interés) |
| `/css/` | Hojas de estilo (sin interés) |
| `/fonts/` | Fuentes web (sin interés) |
| `/vendor/` | Librerías de terceros — ningún archivo relevante expuesto |
| `/js/` | Archivos JavaScript — **aquí se encontró algo interesante** |

También se comprobó la existencia de `robots.txt`, un archivo que a veces revela rutas ocultas:

```
http://10.129.34.243/robots.txt → 404 Not Found
```

<img width="987" height="345" alt="image" src="https://github.com/user-attachments/assets/6abe54f3-c555-46e7-9c34-8420c83d6a97" />


Sin resultado. El servidor no tiene `robots.txt` configurado.

---

## 5. Análisis del código JavaScript

Dentro del directorio `/js/` se encontró un archivo con lógica de validación del formulario de login. El código relevante:

```javascript
$('.validate-form').on('submit', function(){
    var check = true;
    for(var i=0; i<input.length; i++){
        if(validate(input[i]) == false){
            showValidate(input[i]);
            check=false;
        }
    }
    return check;
});

function validate(input) {
    if($(input).attr('type') == 'email' || $(input).attr('name') == 'email') {
        if($(input).val().trim().match(
            /^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}...$/
        ) == null) {
            return false;
        }
    } else {
        if($(input).val().trim() == ''){
            return false;
        }
    }
}
```

**Análisis:**

La validación ocurre **únicamente en el navegador** (client-side). Esto significa:

- El servidor **no valida** los datos por sí mismo antes de procesarlos (o al menos no de forma suficiente).
- Es posible **saltarse la validación** modificando la petición con Burp Suite, curl, o directamente en el campo del formulario.
- La lógica del cliente nunca es una medida de seguridad real.

---

## 6. Explotación — SQL Injection

Con la información recopilada, se procedió a probar si el panel de login era vulnerable a **SQL Injection**. Este tipo de ataque funciona cuando la aplicación construye consultas SQL concatenando directamente el input del usuario, sin sanitizarlo.

Se introdujo el payload clásico de bypass de autenticación en el campo de usuario:

```
Username: ' OR 1=1-- -
Password: (cualquier valor)
```

<img width="987" height="345" alt="image" src="https://github.com/user-attachments/assets/7e7b783c-9fa2-4947-b1f6-7ae062434990" />


**¿Cómo funciona este payload?**

Si el backend ejecuta una consulta como:

```sql
SELECT * FROM users WHERE username='INPUT' AND password='PASS'
```

Al inyectar `' OR 1=1-- -`, la consulta queda:

```sql
SELECT * FROM users WHERE username='' OR 1=1-- -' AND password='...'
```

- La condición `OR 1=1` siempre es verdadera.
- El `-- -` comenta el resto de la consulta, ignorando la verificación de contraseña.
- El resultado es que la consulta devuelve todos los usuarios y la autenticación se bypasea.

**Resultado:** La aplicación aceptó el payload y redirigió a la página de éxito.

---

## 7. Flag obtenida

Tras el bypass exitoso del login, la aplicación mostró la flag:

```
Your flag is: e3d0796d002a446c0e622226f42e9672
```

<img width="889" height="606" alt="image" src="https://github.com/user-attachments/assets/53306d8c-0229-42fe-ba2b-79e5faf708ac" />

---

## 8. Conclusiones y lecciones aprendidas

**Vulnerabilidades identificadas:**

- **SQL Injection en el login** — el campo de usuario no sanitiza el input antes de usarlo en la consulta SQL.
- **Validación solo client-side** — la lógica de validación en JavaScript puede saltarse trivialmente.
- **HTTP sin cifrado** — las credenciales viajan en texto plano por la red.
- **Apache con versión expuesta** — el header `Server: Apache/2.4.38` facilita la búsqueda de CVEs específicos.

**Cómo se podría haber prevenido:**

- Usar **prepared statements** (consultas parametrizadas) en lugar de concatenación de strings en SQL.
- Implementar validación también en el **servidor**, nunca confiar solo en el cliente.
- Configurar HTTPS con un certificado TLS.
- Ocultar la versión del servidor con `ServerTokens Prod` en Apache.

**Herramientas utilizadas:**

| Herramienta | Uso |
|-------------|-----|
| `nmap` | Escaneo de puertos y detección de servicios |
| `gobuster` | Enumeración de directorios y archivos |
| Navegador (DevTools) | Análisis del código fuente y JavaScript |
| Formulario web | Inyección manual del payload SQLi |

---

