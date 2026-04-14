# WebGallery 1.0 — Admin Section

`Realistic` • `Easy` • `10 pts`

## TL;DR

A realistic web challenge simulating a compromised company website. The admin section is accessible via a simple URL, but only responds to the **HTTP `OPTIONS`** method — revealing the password directly in the response body.

**Flag:** `0010110111101001`

---

## Challenge Description

> Rendez-vous dans la section d'administration.
>
> Ne cherchez pas trop compliqué.

The target is a static-looking website for a fictitious software called **WebGallery 1.0**, hosted at:

```
http://challenge01.root-me.org/realiste/ch3/
```

---

## Recon

### Source code analysis

The HTML source reveals:
- A single stylesheet: `format.css`
- An `images/` folder referenced for assets
- No visible link to any admin page
- A story mentioning a past hack that deleted all files

### Directory listing on `/images/`

Browsing to `http://challenge01.root-me.org/realiste/ch3/images/` returns an open directory listing:

| File | Size |
|------|------|
| `Thumbs.db` | 27.5 KiB |
| `fleche-jaune.gif` | 62 B |
| `fleche.gif` | 62 B |
| `header.jpg` | 37.8 KiB |
| `menu.jpg` | 27.1 KiB |
| `news.jpg` | 31.4 KiB |

The presence of `Thumbs.db` is notable — this Windows artifact caches thumbnails of all images that were ever in the folder, including **deleted ones**.

### Thumbs.db forensics

Parsing the OLE compound file with `olefile` and reading the `Catalog` stream reveals filenames of deleted images:

```
test_01.png … test_12.png
footer.jpg
menu copy.jpg
flèche1.jpg
flèche-jaune.gif
```

These were the files deleted after the reported hack — but their thumbnails remain cached. This confirms the site had more content before the incident, though the thumbnails themselves don't contain the flag.

### Finding the admin path

The challenge hints *"don't look too complicated"*. Trying the most obvious path works:

```
http://challenge01.root-me.org/realiste/ch3/admin/
```

A standard `GET` request returns nothing useful, but the key insight is to **test other HTTP methods**.

---

## Exploitation

### HTTP OPTIONS on `/admin/`

```bash
curl -v http://challenge01.root-me.org/realiste/ch3/admin/ -X OPTIONS
```

Response:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
    <title>Admin section</title>
</head>
<body>
    <h1>Mot de passe / password : 0010110111101001</h1>
</body>
```

The server responds **200 OK** to an `OPTIONS` request and leaks the admin password directly in the body.

---

## Why does this work?

The `HTTP OPTIONS` method is meant to advertise which methods a server supports for a given resource. Here, the developer mistakenly used it to serve the admin page content — or left a debug handler in place — making it invisible to standard `GET` browsing but trivially discoverable with any HTTP client.

---

## Key Takeaways

- **Directory listing** can expose sensitive artifacts like `Thumbs.db`, which may leak filenames of deleted files.
- **HTTP method enumeration** (`OPTIONS`, `HEAD`, `PUT`, `TRACE`…) is a basic recon step that is often overlooked.
- A page that returns `404` on `GET` may still respond on other HTTP verbs.
- "Ne cherchez pas trop compliqué" — sometimes the simplest approach is the right one.

---

## References

- [RFC 7231 — HTTP/1.1 Semantics: OPTIONS method](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.7)
- [OWASP — Test HTTP Methods (OTG-CONFIG-006)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods)
- [Thumbs.db forensics — Windows thumbnail cache analysis](https://en.wikipedia.org/wiki/Thumbs.db)