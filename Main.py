import requests
import random
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# ===================== CONFIG =====================
LENGTHS = [3, 4, 5]           # 3-5 letter usernames
WORKER_THREADS = 20           # Adjust for Pyto (iOS safe)
CHECK_SLEEP = 0               # No delay for speed
BIRTHDAY = "1999-04-20"
ROBLOX_API = "https://auth.roblox.com/v1/usernames/validate"

# ===================== GLOBALS =====================
found_usernames = []
found_lock = threading.Lock()
stop_event = threading.Event()

USE_WEBHOOK = False
SHOW_TAKEN = False
WEBHOOK_URL = None

# ===================== FUNCTIONS =====================
def ascii_banner():
    print("""
                                                                                                                                                                                                                                            
      # ###         ##            ##### /             ##        ###          ##       ##### /    ##                                                                                                                                         
    /  /###  /   /####         ######  /           /####       /####       ####  / ######  /  #####                                                                                                                                         
   /  /  ###/   /  ###        /#   /  /           /  ###      /   ###      /####/ /#   /  /     #####                                                                                                                                       
  /  ##   ##       /##       /    /  /               /##           ###    /   ## /    /  ##     # ##                                                                                                                                        
 /  ###           /  ##          /  /               /  ##           ###  /           /  ###     #                                                                                                                                           
##   ##           /  ##         ## ##               /  ##            ###/           ##   ##     #                                                                                                                                           
##   ##   ###    /    ##        ## ##              /    ##            ###           ##   ##     #                                                                                                                                           
##   ##  /###  / /    ##        ## ##              /    ##            /###          ##   ##     #                                                                                                                                           
##   ## /  ###/ /      ##       ## ##             /      ##          /  ###         ##   ##     #                                                                                                                                           
##   ##/    ##  /########       ## ##             /########         /    ###        ##   ##     #                                                                                                                                           
 ##  ##     #  /        ##      #  ##            /        ##       /      ###        ##  ##     #                                                                                                                                           
  ## #      /  #        ##         /             #        ##      /        ###        ## #      #                                                                                                                                           
   ###     /  /####      ##    /##/           / /####      ##    /          ###   /    ###      #                                                                                                                                           
    ######/  /   ####    ## / /  ############/ /   ####    ## / /            ####/      #########                                                                                                                                           
      ###   /     ##      #/ /     #########  /     ##      #/ /              ###         #### ###                                                                                                                                          
            #                #                #                                                 ###                                                                                                                                         
             ##               ##               ##                                   ########     ###                                                                                                                                        
                                                                                  /############  /#                                                                                                                                         
                                                                                 /           ###/                                                                                                                                           
                                                                                                                                                                                                                                            
     ##### /    ##      #######       ##### ##       ##### /##      ##### #     ##       ##            #####   ##    ##       ##### ##             #######       ##### #     ##        #####  #  ##### ##         ##### ##       ##### /##  
  ######  /  #####    /       ###  ######  /### / ######  / ##   ######  /#    #### / /####         ######  /#### #####    ######  /### /        /       ###  ######  /#    #### /  ######  / ######  /###     ######  /### / ######  / ##  
 /#   /  /     ##### /         ## /#   /  / ###/ /#   /  /  ##  /#   /  / ##    ###/ /  ###        /#   /  /  ##### ##### /#   /  / ###/        /         ## /#   /  / ##    ###/  /#   /  / /#   /  /  ###   /#   /  / ###/ /#   /  /  ##  
/    /  ##     # ##  ##        # /    /  /   ## /    /  /   ## /    /  /  ##    # #     /##       /    /  /   # ##  # ## /    /  /   ##         ##        # /    /  /  ##    # #  /    /  / /    /  /    ### /    /  /   ## /    /  /   ##  
    /  ###     #      ###            /  /           /  /    /      /  /    ##   #      /  ##          /  /    #     #        /  /                ###            /  /    ##   #        /  /      /  /      ##     /  /           /  /    /   
   ##   ##     #     ## ###         ## ##          ## ##   /      ## ##    ##   #      /  ##         ## ##    #     #       ## ##               ## ###         ## ##    ##   #       ## ##     ## ##      ##    ## ##          ## ##   /    
   ##   ##     #      ### ###       ## ##          ## ##  /       ## ##     ##  #     /    ##        ## ##    #     #       ## ##                ### ###       ## ##     ##  #       ## ##     ## ##      ##    ## ##          ## ##  /     
   ##   ##     #        ### ###     ## ######      ## ###/        ## ##     ##  #     /    ##        ## ##    #     #       ## ######              ### ###     ## ##     ##  #     /### ##   /### ##      /     ## ######      ## ###/      
   ##   ##     #          ### /##   ## #####       ## ##  ###     ## ##      ## #    /      ##       ## ##    #     #       ## #####                 ### /##   ## ##      ## #    / ### ##  / ### ##     /      ## #####       ## ##  ###   
   ##   ##     #            #/ /##  ## ##          ## ##    ##    ## ##      ## #    /########       ## ##    #     ##      ## ##                      #/ /##  ## ##      ## #       ## ##     ## ######/       ## ##          ## ##    ##  
    ##  ##     #             #/ ##  #  ##          #  ##    ##    #  ##       ###   /        ##      #  ##    #     ##      #  ##                       #/ ##  #  ##       ###  ##   ## ##     ## ######        #  ##          #  ##    ##  
     ## #      #              # /      /              /     ##       /        ###   #        ##         /     #      ##        /                         # /      /        ### ###   #  /      ## ##               /              /     ##  
      ###      /    /##        /   /##/         / /##/      ###  /##/          ##  /####      ##    /##/      #      ##    /##/         /      /##        /   /##/          ##  ###    /       ## ##           /##/         / /##/      ### 
       #######/    /  ########/   /  ##########/ /  ####    ##  /  #####          /   ####    ## / /  #####           ##  /  ##########/      /  ########/   /  #####            #####/        ## ##          /  ##########/ /  ####    ##  
         ####     /     #####    /     ######   /    ##     #  /     ##          /     ##      #/ /     ##               /     ######        /     #####    /     ##               ###    ##   ## ##         /     ######   /    ##     #   
                  |              #              #              #                 #                #                      #                   |              #                            ###   #  /          #              #               
                   \)             ##             ##             ##                ##               ##                     ##                  \)             ##                           ###    /            ##             ##             
                                                                                                                                                                                           #####/                                           
                                                                                                                                                                                             ###                                            
    """)

def terminal_menu():
    global USE_WEBHOOK, WEBHOOK_URL, SHOW_TAKEN

    if input("Show ASCII banner? (y/n): ").strip().lower() == "y":
        ascii_banner()

    SHOW_TAKEN = input("Show taken usernames? (y/n): ").strip().lower() == "y"

    if input("Use Discord webhook? (y/n): ").strip().lower() == "y":
        USE_WEBHOOK = True
        WEBHOOK_URL = input("Enter webhook URL: ").strip()

def send_webhook(msg):
    if not USE_WEBHOOK:
        return
    try:
        requests.post(WEBHOOK_URL, json={"content": msg}, timeout=5)
    except:
        pass

def make_username(length):
    if length == 5:
        # 5-letter usernames: all letters or all numbers
        if random.choice([True, False]):
            return ''.join(random.choice(string.ascii_lowercase) for _ in range(5))
        else:
            return ''.join(random.choice(string.digits) for _ in range(5))
    else:
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

def check_username(username):
    try:
        r = requests.get(
            ROBLOX_API,
            params={"request.username": username, "request.birthday": BIRTHDAY},
            timeout=5
        )
        r.raise_for_status()
        return r.json().get("code")
    except:
        return None

def worker_thread():
    while not stop_event.is_set():
        length = random.choice(LENGTHS)
        username = make_username(length)
        code = check_username(username)

        output = f"Roblox-{length}L-{username}"

        if code == 0:
            with found_lock:
                if username not in found_usernames:
                    found_usernames.append(username)
            print("[FOUND]", output)
            send_webhook(output)
        elif SHOW_TAKEN:
            print("[TAKEN]", output)

        time.sleep(CHECK_SLEEP)

# ===================== MAIN =====================
def main():
    terminal_menu()
    print("\nStarting scanner. Press Ctrl+C to stop.\n")

    with ThreadPoolExecutor(max_workers=WORKER_THREADS) as executor:
        for _ in range(WORKER_THREADS):
            executor.submit(worker_thread)

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            stop_event.set()
            print("\nScanner stopped.")

    print("\nTotal found usernames:", len(found_usernames))

if __name__ == "__main__":
    main()
