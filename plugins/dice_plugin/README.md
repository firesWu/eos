#### DICE_PLUGIN

```
copy -rv dice_plugin eos_dir/plugins/
```

eos_dir/plugins/CMakeLists.txt
```
add_subdirectory(dice_plugin)
```

eos_dir/programs/nodeos/CMakeLists.txt
```
PRIVATE -Wl,${whole_archive_flag} dice_plugin    -Wl,${no_whole_archive_flag}
```

```
./eosio_build.sh
```

···
// maximum action can exec per time
max-action-size-per-trx = 128
// the account who exec reveal action
dice-name = dice
// exec reveal action permission
dice-permission-name = active
// dice contract name
dice-contract-name = dice
// action name which need to exec
dice-action-name = reveal
// dice-name's key,  pub_key=pri_key
dice-signature-provider = EOS6z74gHaPHbd6oQug4xRLAaemhJsBHbVodMXAYexswSpWPWJnUb=5Jq7nTUZJn6k7F3LAd2sLBkPmvZ9GT3jk86kF8DZUewa6dZBeSn
// randkey,  pub_key=pri_key
dice-seed-provider = EOS6ByrykFubC6e9fzhp6ZJM95wyDKq9es6bgKTpMQrsCBWwwUHmX=5KLa8Mr4Uo4nH7uNGJPxKyva8TGgUcPfbj2ja6X9XCyKimDb1FK
···