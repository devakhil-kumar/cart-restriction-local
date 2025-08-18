<script>
    console.log("cart-check.js loaded");

    async function checkCart() {
        console.log("Checking cart...");

        try {
            const cartResponse = await fetch('/cart.js');
            const cartData = await cartResponse.json();

            const items = cartData.items;
            if (!items || items.length === 0) {
                console.log("Cart is empty, skipping location check.");
                return;
            }

            const variantIds = items.map(i => i.variant_id).join(',');
            const shop = "{{ request('shop') ?? '' }}";

            const url = `/apps/local-check-single-location?shop=${shop}&variant_ids=${variantIds}`;

            const response = await fetch(url);
            const data = await response.json();

            console.log("Location check result:", data);

            if (!data.allow_checkout) {
                const checkoutButton = document.querySelector('[name="checkout"]');
                if (checkoutButton) {
                    checkoutButton.disabled = true;
                    checkoutButton.style.opacity = '0.5';
                    checkoutButton.style.cursor = 'not-allowed';
                    checkoutButton.style.pointerEvents = 'none';
                }
                alert("🚫 Checkout blocked due to multiple locations. Please adjust your cart.");
            }
        } catch (err) {
            console.error("Error during location check:", err);
        }
    }

    document.addEventListener('DOMContentLoaded', checkCart);

</script>