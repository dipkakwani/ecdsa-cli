# ECDSA-CLI
A command line interface for digital signatures using elliptic curve digital signature algorithm ([ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm))
### Installation

```sh
$ git clone https://github.com/dipkakwani/ecdsa-cli.git
$ cd ecdsa-cli
```

Create virtual environment and install the dependencies by:

```sh
$ virtualenv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

### Usage
**_Generate public and private keys_**

```sh
$ python ecdsa.py keygen
```
**_Print the keys_**
```sh
$ python ecdsa.py keys
```
**_Sign a message_**

```sh
$ python ecdsa.py sign --message 'Hello world!'
```
or
```sh
$ python ecdsa.py sign
Message: Hello world!
```

**_Verify the sign of a message_**

```sh
$ python ecdsa.py verify --message 'Hello world!' --sign 1234 98765 --key 'public.key'
```
**Help**
```sh
$ python ecdsa.py --help
$ python ecdsa.py verify --help
```

### License
----
MIT
