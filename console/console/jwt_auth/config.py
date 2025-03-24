import os

PUBLIC_KEY = "public.key"
PRIVATE_KEY = "private.key"
KEY_DIR = "keys"

KEY_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), KEY_DIR)
PUBLIC_KEY_LOC = os.path.join(KEY_DIR, PUBLIC_KEY)
PRIVATE_KEY_LOC = os.path.join(KEY_DIR, PUBLIC_KEY)

ACCESS_TOKEN_LIFETIME = 15 * 60  # 15 minutes
REFRESH_TOKEN_DEFAULT_LIFETIME = 60 * 60 * 24  # 24 hours
REFRESH_TOKEN_EXTENDED_LIFETIME = 60 * 60 * 24 * 30  # 30 days
