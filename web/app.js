$scans = document.querySelector('#scans')
$scan = document.querySelector('#scan-result')

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
	fetch('/scans')
		.then(res => res.json())
		.then(renderScans)
}

document.addEventListener("DOMContentLoaded", function(event) { 
	main()
});

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

	const $scaninfo = document.createElement('pre')
	$scaninfo.innerText = JSON.stringify(scan.scaninfo, null, 2)
	$el.appendChild($scaninfo)

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
		fetch('/scans/' + scanID)
			.then(res => res.json())
			.then(renderScan)
	}
}

window.onhashchange = onHashChange
onHashChange()
