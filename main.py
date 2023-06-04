import getopt, sys
import hybrid
import uploadS3
import os
import boto3
import decrypt
import check

def main():
    bucket = None
    object = None
    src = None
    mode = None

    argv = sys.argv[1:]

    try:
        opts, args = getopt.getopt(argv, "b:o:i:m:h:")

    except:
        help_msg()
        sys.exit(2)

    else:
        for opt, arg in opts:
            if opt in ['-h']:
                help_msg()        
                os._exit(0)

            elif opt in ['-m']:
                mode = arg
            elif opt in ['-b']:
                bucket = arg
            elif opt in ['-o']:
                object = arg
            elif opt in ['-i']:
                src = arg
        if (mode == "upload"):
            hybrid.mainMenu(src)
            uploadS3.upload_file(src, bucket, object)
            print("Uploaded Successfully!")

        elif (mode == "download"):
            s3 = boto3.client('s3')
            s3.download_file(bucket, object, src)
            print("File Downloaded!")

        elif (mode == "decrypt"):
            decrypt.main(src)

        elif (mode == "check"):
            check.main()

class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_heading(heading):
    print(Color.BOLD + heading + Color.END)

def help_msg():
    print("\t\t----------------------")
    print(Color.BLUE + "\t\t\tWelcome!!" + Color.END)
    print(Color.BLUE + "\t\tSecure S3 Data Storage" + Color.END)
    print("\t\t----------------------\n")
    print_heading("Check for security issues in S3")
    print("py main.py -m check\n")
    print_heading("Enter text and upload image")
    print("py main.py -m upload -b <bucket-name> -o <object> -i <image-name>\n")
    print_heading("Download an object")
    print("py main.py -m download -b <bucket-name> -o <object> -i <image-name>\n")
    print_heading("Decrypt Image")
    print("py main.py -m decrypt -i <image-name>\n")


if __name__ == '__main__':
    main()
