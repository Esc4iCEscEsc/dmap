function $(selector) {
  return document.querySelector(selector)
}

$scans = $('#scans')
$scan = $('#scan-result')



function renderScans(scans) {
  const arr = Object.keys(scans).reduce((acc, curr) => {
    acc.push(Object.assign(
      scans[curr],
      {id: curr}
    ))
    return acc;
  }, [])

  const sorted = arr.sort((a, b) => {
    return a.finished < b.finished
  })

  sorted.forEach((scan) => {
    const $el = document.createElement('div')
    const hash = scan.id.substr(0,8)

    $link = document.createElement('a')
    $link.innerText = hash + '...'
    $link.href = '#' + scan.id

    $summary = document.createElement('span')
    $summary.style.fontStyle = 'italic'
    $summary.style.marginLeft = '10px'
    $summary.innerText = scan.summary

    $el.appendChild($link)
    $el.appendChild($summary)

    $scans.appendChild($el)
  })
}

function main() {
  token = localStorage.getItem('token')
  fetch('/api/scans', {
    headers: {'Authorization': 'Bearer ' + token}
  })
    .then(res => res.json())
    .then(renderScans)
}

function $info($parent_el, label, value) {
  const $el = document.createElement('div')
  const $title = document.createElement('span')
  $title.innerText = label + ': '
  $title.style.fontWeight = 'bold'
  const $value = document.createElement('span')
  $value.innerText = value

  $el.appendChild($title)
  $el.appendChild($value)
  $parent_el.appendChild($el)
}

function renderScan(scan) {
  const $el = document.createElement('div')
  $el.style.marginBottom = '15px'

  const $title = document.createElement('h3')
  $title.innerText = 'Summary: "' + scan.summary + '"'

  $el.appendChild($title)

  $info($el, 'Arguments', scan.args)
  $info($el, 'Started', scan.started)
  $info($el, 'Finished', scan.finished)
  $info($el, 'Summary', scan.summary)
  $info($el, 'Exit Status', scan.exit)
  $info($el, 'nmap version', scan.nmap_version)
  $info($el, 'XML version', scan.xml_version)

  const $scaninfo = document.createElement('div')

  const $pre = document.createElement('pre')
  $pre.innerText = JSON.stringify(scan.scaninfo, null, 2)

  $el.appendChild($pre)

  const $hosts = document.createElement('pre')
  $hosts.innerText = JSON.stringify(scan.hosts, null, 2)
  $el.appendChild($hosts)

  $scan.innerHTML = ''
  $scan.appendChild($el)
}

var currentHash = ""
function onHashChange() {
  if (window.location.hash !== currentHash) {
    console.log('Hash changed')
    currentHash = window.location.hash
    $scan.innerText = 'Loading...'


    const scanID = currentHash.substr(1)
    const token = localStorage.getItem('token')
    fetch('/api/scans/' + scanID, {
      headers: {'Authorization': 'Bearer ' + token}
    }).then(res => res.json())
      .then(renderScan)
  }
}

window.onhashchange = onHashChange

// main()
onHashChange()

// Authentication part
$auth = $('#auth')
$authError = $('#auth-error')
$authSuccess = $('#auth-success')
$authToken = $('#api-token')
$loginBtn = $('#login-btn')

function tryAuth() {
  let tokenToTry = $authToken.value
  console.log(tokenToTry)
  fetch('/api/scans', {
    headers: {"Authorization": "Bearer " + tokenToTry}
  })
    .then((res) => {
      console.log(res)
      if (res.status === 401) {
        $authError.style.display = 'block'
        console.log('wrong key')
        $authToken.focus();
        $authToken.select();
        return
      }
      if (res.status === 200) {
        $authError.style.display = 'none'
        $authSuccess.style.display = 'block'
        window.localStorage.setItem('token', tokenToTry)
        setTimeout(() => {
          $auth.style.opacity = '0'
          setTimeout(() => {
            $auth.style.display = 'none'
            main()
          }, 250)
        }, 250)
        return
      }
      throw new Error('Didnt handle this kind of statuscode, what gives?')
    })
}

$authToken.onkeypress = function tokenChange(ev) {
  if ($authError.style.display === "block") {
    $authError.style.display = "none"
  }
  if (ev.keyCode === 13) {
    tryAuth()
  }
}

$loginBtn.onclick = tryAuth

if (localStorage.getItem('token')) {
  $authToken.value = localStorage.getItem('token')
  tryAuth();
  $authToken.value = '*************************'
}
