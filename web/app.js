function $(selector) {
  return document.querySelector(selector)
}

function $$(selector) {
  return document.querySelectorAll(selector)
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
    const $el = document.createElement('a')
    const hash = scan.id.substr(0,8)
    $el.href = '#' + scan.id

    $link = document.createElement('span')
    $link.classList = 'link'
    $link.innerText = hash + '...'

    $summary = document.createElement('span')
    $summary.classList = 'summary'
    $summary.style.fontStyle = 'italic'
    $summary.style.marginLeft = '10px'
    $summary.innerText = scan.args

    $el.appendChild($link)
    $el.appendChild($summary)

    $el.id = 'scan-' + scan.id

    $scans.appendChild($el)
  })
  onHashChange()
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
  $value.style.fontFamily = 'monospace'
  $value.innerText = value

  $el.appendChild($title)
  $el.appendChild($value)

  $el.style.marginBottom = '5px'

  $parent_el.appendChild($el)
}

function renderScan(scan) {
  const $el = document.createElement('div')
  $el.style.marginBottom = '15px'

  const $title = document.createElement('h5')
  $title.innerText = scan.id

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

  $scan.innerHTML = $el.innerHTML
  // $scan.innerHTML = ''
  // $scan.appendChild($el)
}

var currentHash = ""
function onHashChange() {
  if (window.location.hash !== currentHash) {
    console.log('Hash changed')
    currentHash = window.location.hash
    $scan.innerText = 'Loading...'


    const scanID = currentHash.substr(1)

    const $scanListItem = $('#scan-' + scanID)
    Array.from($$('.active')).forEach(($el) => {
      $el.classList = ''
    })
    if ($scanListItem) {
      $scanListItem.classList = 'active'
    }

    const token = localStorage.getItem('token')
    fetch('/api/scans/' + scanID, {
      headers: {'Authorization': 'Bearer ' + token}
    }).then(res => res.json())
      .then((res) => renderScan(Object.assign(res, {id: scanID})))
  }
}

window.onhashchange = onHashChange

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
