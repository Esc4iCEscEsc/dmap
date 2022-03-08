function $(selector) {
  return document.querySelector(selector)
}

function $$(selector) {
  return document.querySelectorAll(selector)
}

$scans = $('#scans')
$scan = $('#scan-result')

$searcher = $('#searcher')
$viewer = $('#viewer')

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

  // const $hosts = document.createElement('pre')
  // $hosts.innerText = JSON.stringify(scan.hosts, null, 2)
  // $el.appendChild($hosts)
  const $hosts = document.createElement('div')

  scan.hosts.forEach((host) => {
    const $host = document.createElement('div')
    $host.style.border = '1px solid lightblue'
    $host.style.margin = '3px'
    $host.style.padding = '3px'

    // const $hostAddress = document.createElement('div')
    // $hostAddress.innerText = host.addresses[0].addr
    const $hostAddress = document.createElement('div')
    $hostAddress.innerText = host.addresses.map(el => el.addr).join(', ')

    const $hostStatus = document.createElement('div')
    $hostStatus.innerText = host.status

    const $hostNames = document.createElement('div')
    $hostNames.innerText = host.hostnames.map(el => el.type + ' ' + el.name).join(', ')

    const $ports = document.createElement('div')
    $ports.style.border = '1px solid lightblue'
    $ports.style.margin = '3px'
    $ports.style.padding = '3px'
    host.ports.forEach((port) => {
      const $port = document.createElement('div')
      $port.innerText = port.protocol + ' ' + port.port + ' = ' + port.state + ' (' + port.state_reason + ')'
      if (port.state === 'open') {
        $port.style.color = 'green'
      }
      if (port.state === 'filtered') {
        $port.style.color = 'orange'
      }
      if (port.state === 'closed') {
        $port.style.color = 'red'
      }

      $ports.appendChild($port)
    })

    $host.appendChild($hostAddress)
    $host.appendChild($hostStatus)
    // $host.appendChild($hostAddresses)
    $host.appendChild($hostNames)
    $host.appendChild($ports)
    $hosts.appendChild($host)
  })
  $el.appendChild($hosts)

  $scan.innerHTML = $el.innerHTML
  // $scan.innerHTML = ''
  // $scan.appendChild($el)
}

var currentHash = ""
function onHashChange() {
  const hashContent = window.location.hash.substr(1)

  if (hashContent === 'viewer') {
    $viewer.style.display = 'flex'
    $searcher.style.display = 'none'

    $$('#menu a.active').forEach(el => el.classList = '')

    $('#menu a[href="#viewer"]').classList = 'active'

    return
  }

  if (hashContent === 'searcher') {
    $viewer.style.display = 'none'
    $searcher.style.display = 'flex'

    $$('#menu a.active').forEach(el => el.classList = '')
    $('#menu a[href="#searcher"]').classList = 'active'
    
    return
  }

  $viewer.style.display = 'flex'
  $searcher.style.display = 'none'
  $$('#menu a.active').forEach(el => el.classList = '')
  $('#menu a[href="#viewer"]').classList = 'active'

  if (window.location.hash !== currentHash) {
    console.log('Hash changed')
    currentHash = window.location.hash
    $scan.innerText = 'Loading...'


    const scanID = hashContent

    const $scanListItem = $('#scan-' + scanID)
    Array.from($$('#scans .active')).forEach(($el) => {
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

function debounce(func, timeout = 300){
  let timer;
  return (...args) => {
    clearTimeout(timer)
    timer = setTimeout(() => { func.apply(this, args) }, timeout);
  }
}

$searchTerm = $('#search-term')
$searchResults = $('#search-results')
$searchResultsNum = $('#search-results-num')

function createRow($parent_el, row) {
  const $row = document.createElement('div')
  $row.classList = 'search-result-row'

  const $ip = document.createElement('div')
  $ip.innerText = row.ip

  const $hostname = document.createElement('div')
  $hostname.innerText = row.hostname
  $hostname.title = row.hostname
  $hostname.style.maxWidth = '175px'
  $hostname.style.maxHeight = '19px'
  $hostname.style.overflow = 'hidden'
  $hostname.style.textOverflow = 'ellipsis'
  $hostname.style.wordBreak = 'break-all'

  const $port = document.createElement('div')
  $port.innerText = ":" + row.port

  const $state = document.createElement('div')
  $state.innerText = row.state

  $row.appendChild($ip)
  $row.appendChild($hostname)
  $row.appendChild($port)
  $row.appendChild($state)

  $parent_el.appendChild($row)
}

function renderSearchResults(rows) {
  console.log(rows)
  const $newInner = document.createElement('div')
  $searchResultsNum.innerText = rows.length + " results"

  createRow($newInner, {
    ip: "ip",
    hostname: "hostname",
    port: "port",
    state: "state"
  })

  rows.forEach((row) => {
    createRow($newInner, row)
  })

  console.log('Replacing')
  $searchResults.innerHTML = $newInner.innerHTML
}

function performSearch(term) {
  console.log('searching for', term)
  if (term === "") {
    renderSearchResults([])
    return
  }
  const query = encodeURIComponent(term)
  const url = `/api/search/query/${query}`
  fetch(url, {
    headers: {'Authorization': 'Bearer ' + localStorage.getItem('token')}
  }).then(res => res.json())
    .then(res => renderSearchResults(res))
}

const search = debounce(performSearch, 300)

$searchTerm.onkeyup = function searchTermKeypress(ev) {
  console.log('changed')
  const val = ev.target.value.trim()
  search(val)
}

$('form').onsubmit = async function submitForm(ev) {
  ev.preventDefault()
  console.log('submitting form')

  $('form button').disabled = true
  $('form button').innerText = 'Uploading...'

  const form = ev.currentTarget

  const formData = new FormData(form)

  const request = new XMLHttpRequest();
  request.open('POST', '/api/submit')

  request.setRequestHeader('Authorization', 'Bearer ' + localStorage.getItem('token'))

  request.upload.addEventListener('progress', function(e) {
    const completed = (e.loaded / e.total) * 100;
    console.log(completed)
    $('form button').innerText = 'Uploading ('+Math.floor(completed)+'%)'
    if (completed === 100) {
      $('form button').innerText = 'Processing...'
    }
  })

  request.addEventListener('load', (res) => {
    console.log(res)
    if (request.status !== 201) {
      window.alert(request.status + ' - ' + request.statusText)
      return
    }

    const newHash = request.response
    
    // Too fast and no one realizes it has changed
    setTimeout(() => {
      $('form input[type="file"]').value = ''
      $('form button').disabled = false

      $('form button').innerText = 'Completed!'
      setTimeout(() => {
        $('form button').innerText = 'Upload'
      }, 1000)
    }, 500)

    window.location.hash = newHash
  })

  request.send(formData)

  // const res = await fetch(request)
  // const request = new Request('/api/submit', {
  //   method: 'POST',
  //   // headers: headers,
  //   body: formData,
  // })
  // request.headers.append('Authorization', 'Bearer ' + localStorage.getItem('token'))


  return false
}

if (localStorage.getItem('token')) {
  $authToken.value = localStorage.getItem('token')
  tryAuth();
  $authToken.value = '*************************'
}
