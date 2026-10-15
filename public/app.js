document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('searchForm');
  const domainInput = document.getElementById('domainInput');
  const submitBtn = document.getElementById('submitBtn');
  const spinner = document.getElementById('spinner');
  const btnText = submitBtn.querySelector('.btn-text');

  const resultSection = document.getElementById('resultSection');
  const errorBox = document.getElementById('errorBox');
  const errorMessage = document.getElementById('errorMessage');

  const apiEndpointUrl = document.getElementById('apiEndpointUrl');
  const openApiLink = document.getElementById('openApiLink');

  // Metadata elements
  const resStatus = document.getElementById('resStatus');
  const resSource = document.getElementById('resSource');
  const resTime = document.getElementById('resTime');
  const resDomain = document.getElementById('resDomain');

  // Info card elements
  const infoRegistrar = document.getElementById('infoRegistrar');
  const infoHandle = document.getElementById('infoHandle');
  const infoExpiry = document.getElementById('infoExpiry');
  const infoExpiryCountdown = document.getElementById('infoExpiryCountdown');
  const infoCreated = document.getElementById('infoCreated');
  const infoUpdated = document.getElementById('infoUpdated');
  const infoNameservers = document.getElementById('infoNameservers');
  const infoStatuses = document.getElementById('infoStatuses');
  const jsonOutput = document.getElementById('jsonOutput');
  const copyJsonBtn = document.getElementById('copyJsonBtn');

  let currentJsonData = null;

  // Format date helper
  function formatDate(isoStr) {
    if (!isoStr) return '-';
    try {
      const d = new Date(isoStr);
      return d.toLocaleDateString('id-ID', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        timeZoneName: 'short'
      });
    } catch {
      return isoStr;
    }
  }

  // Calculate days difference
  function getDaysRemaining(isoStr) {
    if (!isoStr) return '';
    try {
      const diff = new Date(isoStr).getTime() - Date.now();
      const days = Math.round(diff / (1000 * 60 * 60 * 24));
      if (days > 0) {
        return `(${days} hari lagi)`;
      } else {
        return `(Kedaluwarsa ${Math.abs(days)} hari lalu)`;
      }
    } catch {
      return '';
    }
  }

  // Fetch WHOIS
  async function fetchWhois(domain) {
    if (!domain) return;

    // Loading UI
    spinner.style.display = 'inline-block';
    btnText.textContent = 'Mengecek...';
    submitBtn.disabled = true;
    errorBox.classList.add('hidden');
    resultSection.classList.add('hidden');

    const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
    const endpoint = `/api/whois?domain=${encodeURIComponent(cleanDomain)}`;
    
    apiEndpointUrl.textContent = endpoint;
    openApiLink.href = endpoint;

    try {
      const response = await fetch(endpoint);
      const data = await response.json();

      if (!response.ok || data.status === 'error') {
        throw new Error(data.message || 'Terjadi kesalahan saat memeriksa domain.');
      }

      currentJsonData = data;
      renderResult(data);

    } catch (err) {
      errorBox.classList.remove('hidden');
      errorMessage.textContent = err.message;
    } finally {
      spinner.style.display = 'none';
      btnText.textContent = 'Cek Domain';
      submitBtn.disabled = false;
    }
  }

  function renderResult(res) {
    const d = res.data;

    resStatus.textContent = '200 OK';
    resSource.textContent = res.source === 'cache' ? '⚡ CACHE (Instan)' : res.source.toUpperCase();
    resTime.textContent = `${res.executionTimeMs} ms`;
    resDomain.textContent = res.domain;

    infoRegistrar.textContent = d.registrar || 'Tidak diketahui';
    infoHandle.textContent = d.registryDomainId ? `Registry ID: ${d.registryDomainId}` : 'No Registry ID';

    infoExpiry.textContent = formatDate(d.expirationDate);
    infoExpiryCountdown.textContent = getDaysRemaining(d.expirationDate);

    infoCreated.textContent = formatDate(d.creationDate);
    infoUpdated.textContent = d.updatedDate ? `Update: ${formatDate(d.updatedDate)}` : 'Update: -';

    // Nameservers
    infoNameservers.innerHTML = '';
    if (d.nameServers && d.nameServers.length > 0) {
      d.nameServers.forEach(ns => {
        const li = document.createElement('li');
        li.textContent = ns;
        infoNameservers.appendChild(li);
      });
    } else {
      infoNameservers.innerHTML = '<li>Tidak ada data nameserver</li>';
    }

    // Statuses
    infoStatuses.innerHTML = '';
    if (d.status && d.status.length > 0) {
      d.status.forEach(st => {
        const tag = document.createElement('span');
        tag.className = 'status-tag';
        tag.textContent = st;
        infoStatuses.appendChild(tag);
      });
    } else {
      infoStatuses.innerHTML = '<span>-</span>';
    }

    // JSON pretty print
    jsonOutput.textContent = JSON.stringify(res, null, 2);

    resultSection.classList.remove('hidden');
  }

  // Handle Form Submit
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    fetchWhois(domainInput.value);
  });

  // Handle Quick Chips
  document.querySelectorAll('.chip').forEach(chip => {
    chip.addEventListener('click', () => {
      domainInput.value = chip.getAttribute('data-domain');
      fetchWhois(domainInput.value);
    });
  });

  // Handle Copy JSON
  copyJsonBtn.addEventListener('click', () => {
    if (!currentJsonData) return;
    navigator.clipboard.writeText(JSON.stringify(currentJsonData, null, 2)).then(() => {
      const originalText = copyJsonBtn.querySelector('span').textContent;
      copyJsonBtn.querySelector('span').textContent = 'Tersalin!';
      setTimeout(() => {
        copyJsonBtn.querySelector('span').textContent = originalText;
      }, 2000);
    });
  });

  // Auto trigger for initial domain
  fetchWhois(domainInput.value || 'dicoding.com');
});
