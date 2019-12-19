
function getFile() {
  return document.getElementById("file").files[0];
}

function encrypt() {
  let file = getFile();
  if(file == undefined) {
      M.toast({html: "Please select a file."})
      return;
  }

  aesGcmEncrypt(file, function(encArrBuf) {
    let blob = new Blob([encArrBuf], {type: "application/octet-stream"});
    saveAs(blob, file.name + ".enc");
  })
}

function decrypt() {
  let file = getFile();
  if(file == undefined || file.name.split(".").pop() != "enc") {
    M.toast({html: "Please select an encrypted file."})
    return;
  }

  aesGcmDecrypt(file, function(decArrBuf) {
    console.log(decArrBuf);
    let blob = new Blob([decArrBuf]);
    saveAs(blob, file.name.substr(0, file.name.indexOf(".enc")))
  })
}

function genKey() {
  pw_input = document.getElementById("input-key-pw");
  generateAesKey(pw_input.value);
  pw_input.value = "";
  M.toast({html: 'Key generated'})

  document.getElementById("btn-do-enc").classList.remove("disabled");
  document.getElementById("btn-do-dec").classList.remove("disabled");
  document.getElementById("btn-do-bench").classList.remove("disabled");
}

function doBench() {
  document.getElementById("api-result").innerHTML = benchmarkApi();
  document.getElementById("asm-result").innerHTML = benchmarkAsm();
  document.getElementById("asm-old-result").innerHTML = benchmarkOldAsm();
}
