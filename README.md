# Curse Catcher

**Curse Catcher** is a script designed to fetch the latest Common Vulnerabilities and Exposures (CVEs) from the **National Institute of Standards and Technology (NIST)** database, filtering for those with a severity score of **9.0 or higher**. This ensures that only the most critical security threats are highlighted, allowing for swift action and mitigation.

## 🎯 Why Curse Catcher?

In the world of cybersecurity, high-severity vulnerabilities (CVSS 9.0+) are like **curses**—dangerous and often catastrophic if left unchecked. **Curse Catcher** acts as a **sentinel**, scanning for these critical threats and bringing them to attention before they can cause harm.

### Key Features:
- 📡 **Fetches the latest CVEs** directly from the **NIST** API.
- 🔥 **Filters vulnerabilities** to only show those with a **CVSS score of 9.0 or higher**.
- 📢 **Outputs critical alerts**, ensuring security teams stay ahead of emerging threats.
- 🛠️ **Easily customizable**, allowing users to tweak filtering criteria if needed.

---

### 1️⃣ Clone the Repository
```
git clone --recursive https://github.com/H4CK-7H3-P14N37/cursecatcher.git
cd cursecatcher
```

### 2️⃣ Setup .env file and add in your variables/api keys
### NOTE: you can get a NIST API [here.](https://nvd.nist.gov/developers/request-an-api-key)
```
cp env.example .env
```

## 🚀 Build the docker image and run it.

Run the script with:

```
./build.sh
./run.sh
```

