console.warn("BeReady.!");
let lastVariantIds = '';
let locationTagCache = null;

(function loadExternalCSS() {
    const cssUrl = 'https://exercises-vital-socks-gt.trycloudflare.com/cart.css'; // Update this URL
    if (!document.querySelector(`link[href="${cssUrl}"]`)) {
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = cssUrl;
        link.type = 'text/css';
        link.media = 'all';
        document.head.appendChild(link);
    }
})();

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadExternalCSS);
} else {
    loadExternalCSS();
}

// Loader
function showLoader() {
    let loader = document.getElementById('location-check-loader');
    if (!loader) {
        loader = document.createElement('div');
        loader.id = 'location-check-loader';
        loader.style = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.4);display:flex;align-items:center;justify-content:center;z-index:9999;';
        loader.innerHTML = `
            <div style="text-align:center;">
                <div style="border:8px solid #f3f3f3; border-top:8px solid #0073e6; border-radius:50%; width:60px; height:60px; animation:spin 1s linear infinite; margin:auto;"></div>
                <div style="margin-top:10px;color:#fff;">Please wait...</div>
            </div>
        `;
        const style = document.createElement('style');
        style.innerHTML = `@keyframes spin{0%{transform:rotate(0deg);}100%{transform:rotate(360deg);}}`;
        document.head.appendChild(style);
        document.body.appendChild(loader);
    }
    loader.style.display = 'flex';
}

function hideLoader() {
    const loader = document.getElementById('location-check-loader');
    if (loader) loader.style.display = 'none';
}

function showToast(message) {
    let toast = document.getElementById('location-conflict-toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'location-conflict-toast';
        toast.style = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#fff8e1;border:1px solid #fbc02d;padding:12px 18px;border-radius:6px;z-index:9999;font-size:14px;max-width:90%;box-shadow:0 2px 8px rgba(0,0,0,0.2);';
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.style.display = 'block';
    setTimeout(() => { toast.style.display = 'none'; }, 6000);
}

async function validateCartBeforeCheckout() {
    console.warn("Validating cart before checkout...");
    showLoader();

    try {
        const cartResponse = await fetch('/cart.js');
        const cartData = await cartResponse.json();
        const items = cartData.items;

        if (!items || items.length === 0) {
            hideLoader();
            return true;
        }

        const variantIds = items.map(i => i.variant_id).join(',');
        const shop = window.Shopify && window.Shopify.shop ? window.Shopify.shop : '';

        if (!shop) {
            console.warn("Shop domain missing, cannot validate.");
            hideLoader();
            return false;
        }

        const url = `/apps/local-check-single-location?shop=${shop}&variant_ids=${variantIds}`;
        const response = await fetch(url);
        const data = await response.json();

        if (!data.allow_checkout) {
            const conflicts = data.conflicts || [];
            window.conflictData = conflicts;
            insertLocationTagsInCart(conflicts);
            injectLocationButtons(conflicts);
            hideLoader();
            return false;
        }

        hideLoader();
        return true;

    } catch (err) {
        console.error("Error during validation:", err);
        hideLoader();
        showToast("Error validating cart. Please try again.");
        return false;
    }
}

// function insertLocationTagsInCart(conflicts) {
//     try {
//         if (!conflicts || conflicts.length === 0) return;

//         conflicts.forEach(item => {
//             const sku = item.sku;
//             const sizeFromName = item.name?.match(/- (\d+)\s*\/|Size: (\d+)/);
//             const size = sizeFromName ? (sizeFromName[1] || sizeFromName[2]) : null;

//             if (!sku || !size) return;

//             const dlElements = Array.from(document.querySelectorAll('dl')).filter(dl => {
//                 const text = dl.textContent.replace(/\s+/g, ' ').trim();
//                 return text.includes(sku) && text.match(new RegExp(`Size:\\s*${size}`));
//             });

//             if (!dlElements.length) return;

//             dlElements.forEach(dl => {
//                 if (dl.querySelector('.location-tag')) return;

//                 const locationTag = document.createElement('div');
//                 locationTag.className = 'location-tag';
//                 locationTag.textContent = `Shipping From ${item.location}`;
//                 locationTag.style.cssText = 'font-family: NHaasGrotesk-Regular; letter-spacing: .05rem; line-height: 1.7; font-size: 14px; text-transform: capitalize; color:#df1818;';
//                 dl.appendChild(locationTag);
//             });
//         });
//     } catch (err) {
//         console.warn('[Location Tag Error]', err);
//     }
// }

function insertLocationTagsInCart(conflicts) {
    try {
        if (!conflicts || conflicts.length === 0) return;

        // Create a map of key -> location
        const locationMap = {};
        for (const item of conflicts) {
            const key = `${item.sku}-${item.size}`;
            locationMap[key] = item.location;
        }

        // Process both cart and drawer
        const dlElements = document.querySelectorAll('dl');

        dlElements.forEach(dl => {
            const text = dl.textContent.replace(/\s+/g, ' ').trim();

            // Extract SKU and Size
            const skuMatch = text.match(/VendorSKU:\s*([^\s,]+)/i);
            const sizeMatch = text.match(/Size:\s*([^\s,]+)/i);

            if (!skuMatch || !sizeMatch) return;

            const sku = skuMatch[1].trim();
            const size = sizeMatch[1].trim();
            const key = `${sku}-${size}`;

            const location = locationMap[key];
            if (!location) return;

            // Avoid duplicates
            if (dl.querySelector('.location-tag')) return;

            const locationTag = document.createElement('div');
            locationTag.className = 'location-tag';
            locationTag.textContent = `Shipping From ${location}`;
            locationTag.style.cssText = 'font-family: NHaasGrotesk-Regular; letter-spacing: .05rem; line-height: 1.7; font-size: 14px; text-transform: capitalize; color:#df1818; margin-top: 6px;';
            dl.appendChild(locationTag);
        });
    } catch (err) {
        console.warn('[Location Tag Error]', err);
    }
}

// function injectLocationButtons(conflicts) {
//     const containers = [
//         document.querySelector('.cartBox'),
//         document.querySelector('.drawer__header')
//     ].filter(Boolean);

//     if (containers.length === 0 || !conflicts || conflicts.length < 2) return;

//     containers.forEach(container => {
//         const existing = container.querySelector('#location-filter-section');
//         if (existing) existing.remove();

//         const wrapper = document.createElement('div');
//         wrapper.id = 'location-filter-section';
//         wrapper.style = `margin-top: 25px; font-family: 'NHaasGrotesk-Regular', sans-serif; display: flex`;

//         const message = document.createElement('div');
//         message.textContent = "Your order cannot be completed since these products are being shipped from different location. Please remove a product before proceeding to checkout.";
//         message.style = `color: #df1818; font-size: 14px; margin-bottom: 14px; line-height: 1.6; width: 68%;`;

//         const buttonWrapper = document.createElement('div');
//         buttonWrapper.style = 'text-align: right;';

//         const result = conflicts.reduce((acc, item) => {
//             const key = `${item.sku}-${item.size}`;
//             acc.grouped[item.location] = acc.grouped[item.location] || [];
//             acc.grouped[item.location].push(key);
//             acc.locationByName[key] = item.location;
//             return acc;
//         }, { grouped: {}, locationByName: {} });

//         Object.entries(result.grouped).forEach(([location, validKeys]) => {
//             const btn = document.createElement('button');
//             btn.textContent = `Keep products from ${location}`;
//             btn.style = `border: 1px solid #000; background: #fff; padding: 10px 18px; font-size: 14px; cursor: pointer; width: 48%; margin: 3px;`;
//             btn.addEventListener('click', async (e) => {
//                 e.preventDefault();
//                 e.stopPropagation();
//                 showLoader();
//                 await removeOtherLocationProductsByLocation(location, result.locationByName, validKeys);
//             });

//             buttonWrapper.appendChild(btn);
//         });

//         wrapper.appendChild(message);
//         wrapper.appendChild(buttonWrapper);
//         container.appendChild(wrapper);
//     });
// }

function injectLocationButtons(conflicts) {
    const containers = [
        { el: document.querySelector('.cartBox'), type: 'cartPage' },
        { el: document.querySelector('.drawer__header'), type: 'drawerRight' }
    ].filter(c => c.el); // Only valid ones

    if (containers.length === 0 || !conflicts || conflicts.length < 2) return;

    // Prepare grouped data
    const result = conflicts.reduce((acc, item) => {
        const key = `${item.sku}-${item.size}`;
        acc.grouped[item.location] = acc.grouped[item.location] || [];
        acc.grouped[item.location].push(key);
        acc.locationByName[key] = item.location;
        return acc;
    }, { grouped: {}, locationByName: {} });

    containers.forEach(({ el: container, type }) => {
        const wrapperId = type === 'cartPage' ? 'location-filter-section-cart' : 'location-filter-section-drawerRight';

        const existing = container.querySelector(`#${wrapperId}`);
        if (existing) existing.remove();

        const wrapper = document.createElement('div');
        wrapper.id = wrapperId;
        wrapper.className = `location-filter-wrapper ${type}`;

        const message = document.createElement('div');
        message.className = 'leftDiv';
        message.textContent = "Your order cannot be completed since these products are being shipped from different location. Please remove a product before proceeding to checkout.";

        const buttonWrapper = document.createElement('div');
        buttonWrapper.className = 'rightDiv';

        Object.entries(result.grouped).forEach(([location, validKeys]) => {
            const btn = document.createElement('button');
            btn.textContent = `Keep products from ${location}`;
            btn.className = `location-btn ${type}`; // You can style `.location-btn.drawer` separately if needed
            btn.style = `
               
            `;
            btn.addEventListener('click', async (e) => {
                e.preventDefault();
                e.stopPropagation();
                showLoader();
                await removeOtherLocationProductsByLocation(location, result.locationByName, validKeys);
            });

            buttonWrapper.appendChild(btn);
        });

        wrapper.appendChild(message);
        wrapper.appendChild(buttonWrapper);
        container.appendChild(wrapper);
    });
}

async function removeOtherLocationProductsByLocation(selectedLocation, locationByName, validKeys) {
    try {
        const cartResp = await fetch('/cart.js');
        const cartData = await cartResp.json();
        const items = cartData.items;

        for (const item of items) {
            const itemSku = item.sku || '';
            const itemKey = item.key;

            let itemSize = item.options_with_values?.find(opt => opt.name === "Size")?.value || '';
            if (!itemSize) {
                const sizeFromTitle = item.title.match(/-\s*(\d+(?:\.\d+)?)/);
                itemSize = sizeFromTitle ? sizeFromTitle[1] : '';
            }

            const key = `${itemSku}-${itemSize}`;
            const shouldKeep = validKeys.includes(key);

            if (!shouldKeep) {
                console.log(`Removing item: ${item.title} | key: ${key}`);
                const resp = await fetch(`/cart/change.js`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id: itemKey, quantity: 0 })
                });

                const resJson = await resp.json();
                console.log(`✔ Removed: ${item.title}`, resJson);
            }
        }

        hideLoader();
        window.location.reload();
    } catch (err) {
        console.error("Error during location-based cleanup:", err);
        hideLoader();
        showToast("Failed to update cart. Please try again.");
    }
}

function bindCheckoutValidation() {
    document.querySelectorAll('form[action="/checkout"]').forEach(form => {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            e.stopPropagation();
            const allowed = await validateCartBeforeCheckout();
            if (allowed) form.submit();
        });
    });

    bindDynamicCheckoutButtons();

    const observer = new MutationObserver(() => {
        bindDynamicCheckoutButtons();
    });

    observer.observe(document.body, { childList: true, subtree: true });
}

function bindDynamicCheckoutButtons() {
    document.querySelectorAll('#CartDrawer-Checkout, #LocalcHeckOoutlocal').forEach(button => {
        if (button.dataset.bound !== "true") {
            button.dataset.bound = "true";
            button.addEventListener('click', async (e) => {
                e.preventDefault();
                e.stopPropagation();
                button.disabled = true;
                const allowed = await validateCartBeforeCheckout();
                if (allowed) {
                    window.location.href = '/checkout';
                } else {
                    button.disabled = false;
                }
            });
        }
    });
}

// Initialize
(function () {
    const init = () => {
        bindCheckoutValidation();
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    const observer = new MutationObserver(() => {
        bindCheckoutValidation();
    });

    observer.observe(document.body, { childList: true, subtree: true });
})();
