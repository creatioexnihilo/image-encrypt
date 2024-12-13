
# 🖼️ Image Encrypt

A Python desktop application that encrypts text into images and decrypts the images back into text using a secret key. This project ensures secure transformation of sensitive data into a visual form.

---

## 📚 Features
- 🔐 **Encrypt Text into Images**: Convert plain text into encrypted images.
- 🔓 **Decrypt Images Back to Text**: Extract and retrieve the original text from an encrypted image.
- 🗝️ **Key-Based Encryption**: Use a secret key to encrypt and decrypt data.
- 🖥️ **Desktop Application**: Simple and intuitive to run locally.

---

## 🔧 Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.6+**
- **Pipenv** (for managing the virtual environment and dependencies)

To install **Pipenv**, run:
```bash
pip install pipenv

# 📥 Installation

### Clone the Repository:
```bash
git clone https://github.com/creatioexnihilo/image-encrypt.git
cd image-encrypt
```
### Install Dependencies:
```bash
pipenv install
```

### Install from requirements.txt (optional):
```bash
pipenv run pip install -r requirements.txt
```
## 🚀 Usage

### Activate the Virtual Environment:
```bash
pipenv shell
```

### Run the Application:
```bash
python main.py
```

### How to Use:
- **Encrypt Text**: Enter the text, provide a key, and click **Encrypt**.
- **Decrypt Image**: Load the encrypted image, enter the key, and click **Decrypt** to extract the text.
## 🛠️ Project Structure
```
📁 image-encrypt/
 ┣ 📜 Pipfile
 ┣ 📜 Pipfile.lock
 ┣ 📜 requirements.txt
 ┣ 📜 main.py  # Main script to run the application
 ┗ 📜 LICENSE  # License file
```

---

## 🔄 Exiting the Virtual Environment

To deactivate the virtual environment, type:
```bash
exit
```
This will return you to your system's global Python environment.

---

## 🔄 Commands Reference

### Install new package:
```bash
pipenv install package-name
```

### Install dev package (for development only):
```bash
pipenv install --dev package-name
```

### List installed packages:
```bash
pipenv graph
```

### Update dependencies:
```bash
pipenv update
```

---

## 📝 Author

- **creatioexnihilo** - [GitHub Profile](https://github.com/creatioexnihilo)

---

## 💬 Support

If you find this project helpful, consider supporting me on [☕ Buy Me a Coffee](https://www.buymeacoffee.com/creatioexnihilo).

---

Happy encrypting! 🔐🖼️
