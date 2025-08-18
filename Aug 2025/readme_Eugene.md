🤖 **The AI Hype Train Derailment** 

*"We need more AI!"* - every boss ever

Your company jumped on the AI bandwagon and tasked you with building something "revolutionary." So naturally, you grabbed the first shiny library you could find - `libsvm-wasm` - and cobbled together a model training server for your team.

It seemed like such a good idea at the time... 🤔

But now you're starting to wonder: **What could go wrong?** (Spoiler alert: probably everything)

Time to put on your security researcher hat and find out just how "intelligent" this artificial intelligence really is. Can you discover the vulnerability hiding in your rushed AI implementation?

## 🎯 Your Mission
- Analyze the model training server and find the security flaw
- Exploit the vulnerability to get the flag
- Submit your solution via [this form](https://forms.gle/r9UF5LMqE7vsHpjo7)
- Share your writeup - we want to see your thought process!

## 🔧 Challenge Setup
- **Files**: Download all repo files (excluding `SOLUTION.md` - no spoilers!)
- **Local Testing**:
  ```shell
  docker build -t zero-day-pwnable --platform linux/amd64 .
  docker run --platform linux/amd64 --rm -p 3000:3000 -e FLAG=customflag zero-day-pwnable
  ```
- **Target**: `http://159.223.33.156:9103/`

**Ready to debug your AI dreams?** Sometimes the real artificial intelligence was the vulnerabilities we made along the way... 😅🚀

*Good luck, and remember - just because it has "AI" in the name doesn't make it smart!* 🧠💥