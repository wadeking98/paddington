# Paddington
## Padding oracles aren't dead!

Long believed to be an archaic exploit that doesn't show up on much aside from the occasional CTF,  
The general sentiment around padding oracles is that they might be interesting, but a tester is not likely to  
run into them in the wild.  

This is mainly due to the fact that traditional padding oracles rely on there being two different error  
messages, a padding error and a data error. And most developers these days know better than to disclose a  
padding error.  

However, it turns out that a padding error is not needed most of the time. If you can find or create a section  
at the end of the ciphertext where it is impossible to generate a data error, then any error resulting from  
manipulating that region of the ciphertext must be padding error!  

This is called a "double ciphertext attack" and it is very simple to execute, just take a copy of the  
ciphertext and append it to the origional text. Many applications will stop reading the data after they've  
gotten all the information they need, this means that the second copy of the ciphertext is unchecked by the  
application, but the padding is still checked by the decryptor. This is what enables the attack.  
  
Additionally, it may be possible to perform an intermediate ciphertext attack where a section of data allows  
some random bytes, and error messages are tied with the presence of a certain character. An example would  
be a plaintext JSON object string attribute `{"foo":"couple blocks of string content here"}`  

If the JSON object allows random bytes in the string then an attack might look like this:  
`{"foo":"[RANDOM_BYTES]couple [X]locks of string content here"}`  

The attacker iterates over the last byte of the iv until it writes a `"` character at the `[X]` position. 

The resulting plaintext is invalid json and throws an error, which tells the attacker they've just written  
a quotation mark. This can be used to perform a padding oracle attack since the attacker knows they've  
written a certain byte to a certain position. Note that no padding was actually used in this attack,  
opening up possibilities of exploiting other AES modes like CFB and OFB which don't use padding.  

## Attention: the intermediate ciphertext attack has now been implemented. 
Paddington should automatically detect and exploit intermediate ciphertext attacks. Note that this type of
attack is very time-consuming, so be patient. Depending on the size of the ciphertext and speed of the
connection, expect at least 20 minutes - 1 hour.

## Usage
```
Padding Oracles Ain't Dead!

Usage: paddington [OPTIONS] --url <URL>

Options:
  -u, --url <URL>                url for the vulnerable endpoint
  -p, --params <PARAMS>          params to scan, can be url parameters, body parameters, or headers, alternatively surround the value you want to analyze with "@{ }@"
  -H, --headers <HEADERS>        add headers to the request
  -d, --data <DATA>              add the request body
  -m, --method <METHOD>          the request method to use [default: GET]
  -e, --encoding <ENCODING>      the encoding to use for the bytes, you can specify multiple encodings and they will be used in order.
                                 example: if a string is base64 encoded then URL encoded, use "-e url" to url decode, and then 
                                 "-e b64" to base64 decode [default: b64] [possible values: hex, b64, b64-url, url]
  -t, --threads <THREADS>        the number of threads to use [default: 10]
  -f, --forge <FORGE>            the plaintext to forge
  -b, --block-size <BLOCK_SIZE>  the block size to use (small = 8) (med = 16) (large = 32) [default: AUTO] [possible values: small, med, large, auto]
  -s, --search-pat <SEARCH_PAT>  the search string to match a response with valid padding
      --proxy <PROXY>            the proxy to use
  -c, --ciphertext <CIPHERTEXT>  override the ciphertext to use
  -i, --iv <IV>                  add a prefix to the ciphertext (IV) encoded the same way as the ciphertext
  -a, --attack <ATTACK>          the attack type to use, (single = standard attack) (double = double ciphertext attack) 
                                 (inter = intermediate ciphertext attack) [default: ALL] [possible values: double, single, inter, all]
  -r, --retry <RETRY>            number of times to retry when no valid byte found [default: 5]
      --bad-chars <BAD_CHARS>    known bad characters used for intermediate oracle. You don't need to list all invalid bytes for the attack to work, only a few are needed. The default configuration is best for JSON on Node, PHP, etc. The intermediate oracle doesn't work great for most Python apps at the moment. add bad bytes like so '\x00\x01\x02"\xff}{[]!'
  -h, --help                     Print help
  -V, --version                  Print version
```

## Install
> git clone https://github.com/wadeking98/paddington.git  
> cd paddington  
> cargo build --release  
> ./target/release/paddington -h
