# Manual hardware checklist

The FIDO2 layer has no mock authenticator, so these steps are a release gate.
Run them on real hardware before tagging a release: a YubiKey 5 and a
Trezor Safe 3. Use a throwaway `--dir` for each run.

## Two keys, one keyring

1. `wardlet --dir /tmp/check-a init` with the first key. Save the recovery code.
2. Confirm the saved code when asked (default is No; you must answer `y`).
3. Add the second key when offered, with a different label.
4. `wardlet --dir /tmp/check-a enc <file>`: each key in turn (unplug the other)
   can run `wardlet --dir /tmp/check-a dec <file>.age`.
5. Remove one key's wrapper file (`keys/<id>.mask`) copy aside, corrupt the
   other copy in a scratch keyring, and confirm unlock still works with the
   remaining good key.

## Change keys (rotation)

1. `wardlet --dir /tmp/check-a config`: add a third key (or remove one), quit.
2. Save the new recovery code shown for this visit.
3. Files encrypted before the change still decrypt with every remaining key.
4. Files encrypted after the change decrypt with every remaining key.
5. The previous recovery code opens only files from before the change.
6. The new recovery code opens everything.
7. Declining the new recovery code in a second visit leaves the keyring
   unchanged: the code from step 2 still works and no version bump appears in
   `wardlet --dir /tmp/check-a status`.

## Export and import on a second keyring directory

1. `wardlet --dir /tmp/check-a export /tmp/check.wardlet`
2. `wardlet --dir /tmp/check-b import /tmp/check.wardlet`
3. On the imported copy, `status` shows the same version, and both keys
   decrypt files encrypted by either copy.
4. The recovery code is not inside the export: importing alone does not let
   anyone add a key without the current recovery code or a hardware key.

## Wrong key and wrong code

1. A hardware key that was never enrolled does not unlock (`dec` fails and
   prints that the key or code does not open the keyring).
2. A mistyped recovery code in `wardlet recover` fails the same way.
3. The last remaining key cannot be removed in `wardlet config`.

## Editor round trip

1. With `EDITOR` set to a terminal editor, `wardlet edit notes.txt.age`
   shows the plaintext, and quitting re-encrypts it in place.
2. Open the same file, change the ciphertext from another shell while the
   editor is open, quit: Wardlet refuses to replace it and names the
   plaintext left behind.
3. `wardlet new fresh.txt` creates `fresh.txt.age` after the editor quits,
   and a failing editor leaves the plaintext with its path printed.

## Sign-off

Record for each release: date, binary version (`wardlet version`), the two
devices and firmware versions, and pass/fail per section above.
