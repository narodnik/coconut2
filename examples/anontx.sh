#!/bin/bash
DF="./target/debug/examples/df"

############################################################
echo "Initializing..."
INIT=$($DF init 5 7)
SECRET_KEY1=$(echo "$INIT" | head -1 | awk '{print $2}')
SECRET_KEY2=$(echo "$INIT" | head -2 | tail -1 | awk '{print $2}')
SECRET_KEY3=$(echo "$INIT" | head -3 | tail -1 | awk '{print $2}')
SECRET_KEY4=$(echo "$INIT" | head -4 | tail -1 | awk '{print $2}')
SECRET_KEY5=$(echo "$INIT" | head -5 | tail -1 | awk '{print $2}')
SECRET_KEY6=$(echo "$INIT" | head -6 | tail -1 | awk '{print $2}')
SECRET_KEY7=$(echo "$INIT" | head -7 | tail -1 | awk '{print $2}')
VERIFY_KEY=$(echo "$INIT" | tail -1 | awk '{print $2}')
echo "Done."

echo $SECRET_KEY1 > /tmp/skey1
echo $SECRET_KEY2 > /tmp/skey2
echo $SECRET_KEY3 > /tmp/skey3
echo $SECRET_KEY4 > /tmp/skey4
echo $SECRET_KEY5 > /tmp/skey5
echo $SECRET_KEY6 > /tmp/skey6
echo $SECRET_KEY7 > /tmp/skey7
echo $VERIFY_KEY > /tmp/vkey
############################################################

SECRET_KEY1=$(cat /tmp/skey1)
SECRET_KEY2=$(cat /tmp/skey2)
SECRET_KEY3=$(cat /tmp/skey3)
SECRET_KEY4=$(cat /tmp/skey4)
SECRET_KEY5=$(cat /tmp/skey5)
SECRET_KEY6=$(cat /tmp/skey6)
SECRET_KEY7=$(cat /tmp/skey7)
VERIFY_KEY=$(cat /tmp/vkey)

run_service() {
    echo "Run service $1"
    rm -f /tmp/service$1_input
    rm -f /tmp/service$1_output
    mkfifo /tmp/service$1_input
    mkfifo /tmp/service$1_output
    var="SECRET_KEY$1"
    SECRET_KEY=${!var}
    $DF run-service $SECRET_KEY $VERIFY_KEY $1 \
        < /tmp/service$1_input > /tmp/service$1_output &
}

run_service 1
run_service 2
run_service 3
run_service 4
run_service 5
run_service 6
run_service 7

echoerr() { echo "$@" 1>&2; }

read_value() {
    VALUE=$(echo "${!2}" | head -1 | awk '{print $2}')
    declare -g "$1"="$VALUE"
    declare -g "$2"="$(echo "${!2}" | tail -n +2)"
}
select_input() {
    echo "$1" | $2 | awk '{print $2}'
}
first() {
    select_input "$1" "head -1"
}
last() {
    select_input "$1" "tail -1"
}

deposit() {
    TOKEN_VALUE="$1"
    TOKEN_SECRET="$2"
    TX=$($DF tx new)

    echoerr deposit: Created tx

    NEW_OUTPUT=$($DF output new $TOKEN_SECRET)
    read_value OUTPUT           NEW_OUTPUT
    read_value OUTPUT_SECRET    NEW_OUTPUT
    #echo output is $OUTPUT
    #echo output secret is $OUTPUT_SECRET

    echoerr deposit: Created new output for our token

    TX=$($DF tx add-deposit $TOKEN_VALUE $TX)
    ADD_OUT_OP=$($DF tx add-output $OUTPUT $TX)
    read_value TX               ADD_OUT_OP
    read_value OUTPUT_ID        ADD_OUT_OP

    PEDERSENS=$($DF tx compute-pedersens $TX -o $TOKEN_VALUE)
    read_value OUTPUT_BLIND     PEDERSENS
    read_value TX               PEDERSENS

    echoerr deposit: Pedersens computed

    OUTPUT_SECRET=$($DF output setup-secret $OUTPUT_SECRET $OUTPUT_BLIND)
    echoerr deposit: Setup secret

    OUTPUT_COMMITS=$($DF output commits $OUTPUT_SECRET)
    echoerr deposit: Created proof commits

    CHALLENGE=$($DF hash-challenge -o $OUTPUT_COMMITS)
    echoerr deposit: Hashed proof challenge

    OUTPUT_PROOF=$($DF output proof $OUTPUT_SECRET $CHALLENGE)
    echoerr deposit: Generated proofs

    TX=$($DF tx set-output-proof $TX $OUTPUT_ID $OUTPUT_PROOF)
    TX=$($DF tx set-challenge $TX $CHALLENGE)

    echoerr deposit: Begin signing.

    echo $TX > /tmp/service1_input &
    echo $TX > /tmp/service3_input &
    echo $TX > /tmp/service4_input &
    echo $TX > /tmp/service2_input &
    echo $TX > /tmp/service7_input &

    read SIGNATURE1 < /tmp/service1_output
    read SIGNATURE3 < /tmp/service3_output
    read SIGNATURE4 < /tmp/service4_output
    read SIGNATURE2 < /tmp/service2_output
    read SIGNATURE7 < /tmp/service7_output

    echoerr deposit: Unblind partial signature shares from services

    TOKEN=$($DF tx unblind $TX -t $TOKEN_SECRET -s $SIGNATURE1 -s $SIGNATURE3 -s $SIGNATURE4 -s $SIGNATURE2 -s $SIGNATURE7)
    echo $TOKEN
}

splitargs() {
    DATA=$(cat)

    argc=$#
    argv=("$@")

    for (( j=0; j<argc; j++ )); do
        INDEX=$(( j + 1 ))
        VALUE=$(echo "$DATA" | head -$INDEX | tail -1 | awk '{print $2}')
        # This not accessible globally for some reason
        declare -g "${argv[j]}"="$VALUE"
    done
}

split() {
    TOKEN_VALUE="$1"
    TOKEN_SECRET="$2"

    TOKEN1_VALUE="$3"
    TOKEN1_SECRET="$4"

    TOKEN2_VALUE="$5"
    TOKEN2_SECRET="$6"

    TX=$($DF tx new)

    echoerr split: Created tx

    NEW_INPUT=$($DF input new $VERIFY_KEY $TOKEN $TOKEN_SECRET)
    read_value INPUT            NEW_INPUT
    read_value INPUT_SECRET     NEW_INPUT

    NEW_OUTPUT=$($DF output new $TOKEN1_SECRET)
    read_value OUTPUT1          NEW_OUTPUT
    read_value OUTPUT1_SECRET   NEW_OUTPUT

    # Wallet 2 does this to receive their token
    NEW_OUTPUT=$($DF output new $TOKEN2_SECRET)
    read_value OUTPUT2          NEW_OUTPUT
    read_value OUTPUT2_SECRET   NEW_OUTPUT

    echoerr split: Created 1 input and 2 new output for our token

    ADD_IN_OP=$($DF tx add-input $INPUT $TX)
    read_value TX               ADD_IN_OP
    read_value INPUT_ID         ADD_IN_OP

    ADD_OUT_OP=$($DF tx add-output $OUTPUT1 $TX)
    read_value TX               ADD_OUT_OP
    read_value OUTPUT1_ID       ADD_OUT_OP

    ADD_OUT_OP=$($DF tx add-output $OUTPUT2 $TX)
    read_value TX               ADD_OUT_OP
    read_value OUTPUT2_ID       ADD_OUT_OP

    PEDERSENS=$($DF tx compute-pedersens $TX -i $TOKEN_VALUE -o $TOKEN1_VALUE -o $TOKEN2_VALUE)
    read_value INPUT_BLIND      PEDERSENS
    read_value OUTPUT1_BLIND    PEDERSENS
    read_value OUTPUT2_BLIND    PEDERSENS
    read_value TX               PEDERSENS

    INPUT_SECRET=$($DF input setup-secret $VERIFY_KEY $INPUT_SECRET $INPUT_BLIND)
    OUTPUT1_SECRET=$($DF output setup-secret $OUTPUT1_SECRET $OUTPUT1_BLIND)
    OUTPUT2_SECRET=$($DF output setup-secret $OUTPUT2_SECRET $OUTPUT2_BLIND)
    echoerr split: Setup secret

    INPUT_COMMITS=$($DF input commits $VERIFY_KEY $INPUT_SECRET)
    OUTPUT1_COMMITS=$($DF output commits $OUTPUT1_SECRET)
    OUTPUT2_COMMITS=$($DF output commits $OUTPUT2_SECRET)
    echoerr split: Created proof commits

    CHALLENGE=$($DF hash-challenge -i $INPUT_COMMITS -o $OUTPUT1_COMMITS -o $OUTPUT2_COMMITS)
    echoerr split: Hashed proof challenge

    INPUT_PROOF=$($DF input proof $VERIFY_KEY $INPUT_SECRET $CHALLENGE)
    OUTPUT1_PROOF=$($DF output proof $OUTPUT1_SECRET $CHALLENGE)
    OUTPUT2_PROOF=$($DF output proof $OUTPUT2_SECRET $CHALLENGE)
    echoerr split: Generated proofs

    TX=$($DF tx set-input-proof $TX $INPUT_ID $INPUT_PROOF)
    TX=$($DF tx set-output-proof $TX $OUTPUT1_ID $OUTPUT1_PROOF)
    TX=$($DF tx set-output-proof $TX $OUTPUT2_ID $OUTPUT2_PROOF)
    TX=$($DF tx set-challenge $TX $CHALLENGE)

    echoerr split: Begin signing.
    echoerr split: BTW when this script does the deposit step then below will
    echoerr split: hang eventhough the signing is successful.
    echoerr split: TODO: fix this bash script

    echo $TX > /tmp/service1_input &
    echo $TX > /tmp/service3_input &
    echo $TX > /tmp/service4_input &
    echo $TX > /tmp/service2_input &
    echo $TX > /tmp/service7_input &

    read SIGNATURE1 < /tmp/service1_output
    read SIGNATURE3 < /tmp/service3_output
    read SIGNATURE4 < /tmp/service4_output
    read SIGNATURE2 < /tmp/service2_output
    read SIGNATURE7 < /tmp/service7_output

    echoerr split: Unblind partial signature shares from services

    TOKENS=$($DF tx unblind $TX -t $TOKEN1_SECRET -t $TOKEN2_SECRET -s $SIGNATURE1 -s $SIGNATURE3 -s $SIGNATURE4 -s $SIGNATURE2 -s $SIGNATURE7)
    echo $TOKENS
}

# Deposit 110 BTC, get a token worth 110 BTC

TOKEN_VALUE=110
TOKEN_SECRET=$($DF token new-secret $TOKEN_VALUE)

echo "Created new token secret: $TOKEN_SECRET"

############################################################
TOKEN=$(deposit $TOKEN_VALUE $TOKEN_SECRET)
echo "Created token: $TOKEN"
echo $TOKEN_SECRET > /tmp/token_secret
echo $TOKEN > /tmp/token
############################################################

TOKEN_SECRET=$(cat /tmp/token_secret)
TOKEN=$(cat /tmp/token)

# Split & send our token of 110 into 100 and 10, sending the 10 one

TOKEN1_VALUE=100
TOKEN1_SECRET=$($DF token new-secret $TOKEN1_VALUE)

TOKEN2_VALUE=10
TOKEN2_SECRET=$($DF token new-secret $TOKEN2_VALUE)

SPLIT_TOKENS=$(split $TOKEN_VALUE $TOKEN_SECRET $TOKEN1_VALUE $TOKEN1_SECRET $TOKEN2_VALUE $TOKEN2_SECRET)
echo "returned $SPLIT_TOKENS"
read_value TOKEN1   SPLIT_TOKENS
read_value TOKEN2   SPLIT_TOKENS

echo Token 1 is "$TOKEN1"
echo Token 2 is "$TOKEN1"

echo exit > /tmp/service1_input
echo exit > /tmp/service3_input
echo exit > /tmp/service4_input
echo exit > /tmp/service2_input
echo exit > /tmp/service7_input

