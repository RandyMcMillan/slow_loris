# A slow loris implementation written in Rust
The slow loris attack is a special kind of Denial-of-service attack.
In comparison to other attacks of it's kind, it needs just a small amount of bandwidth and a single
computer and is still super effective! Primary targets are Apache server or other servers that spawn new
threads for each request to handle and that have limitations to how many requests they handle at once.
But it also profoundly affects the performance of other server types.

To be able to understand slow loris, you should know something about the HTTP protocol, the protocol used 
to make requests on the internet. This protocol has the property that an HTTP request always ends with two 
new lines (\n\n). And servers are programmed to wait for these two lines.  
But of course, sometimes a client doesn't send these two lines, cause for example the power of his phone 
drained. In these cases, the server usually kills the connection after a few seconds.  
So the first idea would be just to keep sending useless stuff forever, right? There's just one
little problem: The guys who program servers are pretty intelligent and created things like size
limits for requests.  

The slow loris solves this problem. It works by spawning (just) a few hundred to thousand threads. Each
of these threads then tries to connect to the attacked server. If a connection is established, the slow
loris trick comes into place:  
This thread does not just send useless stuff to the server. It sends this useless stuff at an incredibly 
slow speed (about one byte every 5 to 10 seconds | ~ 1 bit/s (usual speed
is about 50+ Mbit/s or 50_000_000 bit/s !)). So the slow loris basically simulates a painfully slow
internet connection. And since a few thousand threads do the same, the server has no time to serve
anyone except the attacker.

So what is the brilliant thing about it? First, most servers can't defend themself against such an attack,
simply cause you can't distinguish between someone with slow internet and slow loris. And second, cause
slow loris doesn't send enough requests to get blocked as other Dos attacks do.

So all in all:  
Slow loris does extremely well in bringing servers down without the requirement of 
thousands of PCs like usual Dos attacks.
 
 ## You want to try it (on a server you have the permission to attack!)?
 
### Requirements
- The Rust compiler
- A Server you're allowed to attack
- An internet connection
- A PC capable of handling a few thousands of threads (usually satisfied)

### Usage
`slow_loris.exe [OPTIONS] <address>`

To simply start an attack with the default parameter type (where <domain|ip-address> is the domain or IP
of the server you want to attack):  
`cargo run --release -- <domain|ip-address>`

##### OPTIONS:
To set the maximum amount of connections possible:  
`-c | --conections <amount of connections>`

To set the timeout between individual bytes:   
`-t | --timeout [<amount of seconds> | <min-timeout>..<max-timeout-exclusive> | <min-timeout>..=<max-timeout-inclusive>]`

To set the length of the body that is send:  
`-b | --body_lenght [<amount of character> | <min-length>..<max-length-exclusive> | <min-length>..=<max-length-inclusive>]`

##### End the attack
To stop the attack just press [Ctrl]+[c]

---
### Contribute
You found a bug, or you have an idea to improve the code? Just open an issue or send a push request!
