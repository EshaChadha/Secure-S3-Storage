import getopt, sys
import hybrid
import uploadS3
import os
import boto3
import decrypt

def main():
    bucket = None
    object = None
    src = None
    mode = None

    argv = sys.argv[1:]

    try:
        opts, args = getopt.getopt(argv, "b:o:i:m:h:")

    except:
        print ("usage: python3 main.py -m upload -b <bucket-name> -o <object> -i <image-name>")
        print ("usage: python3 main.py -m download -b <bucket-name> -o <object> -i <image-name>")
        print("usage: python3 main.py -m decrypt -i <image-name>")
        sys.exit(2)

    else:
        for opt, arg in opts:
            if opt in ['-h']:
                print ("usage: python3 main.py -m upload -b <bucket-name> -o <object> -i <image-name>")
                print ("usage: python3 main.py -m download -b <bucket-name> -o <object> -i <image-name>")
                print ("usage: python3 main.py -m decrypt -i <image-name>")
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
            print("Uploaded Successfully!!!")

        elif (mode == "download"):
            s3 = boto3.client('s3')
            s3.download_file(bucket, object, src)
            print("File Downloaded!!!")

        elif (mode == "decrypt"):
            decrypt.main(src)

if __name__ == '__main__':
    main()