(() => {
    const page = document.documentElement;
    const status = document.getElementById('registration-status');
    const form = document.getElementById('resume-authentication');
    const deadline = Date.now() + 180000;
    const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

    async function poll() {
        if (Date.now() >= deadline) {
            status.textContent = '登録を確認できませんでした。認証を最初からやり直してください。';
            return;
        }
        try {
            const response = await fetch(page.dataset.statusUrl, {
                credentials: 'same-origin',
                cache: 'no-store'
            });
            if (response.status === 410) {
                status.textContent = '登録challengeの有効期限が切れました。認証を最初からやり直してください。';
                return;
            }
            if (!response.ok) {
                throw new Error('registration status unavailable');
            }
            const result = await response.json();
            if (result.registered) {
                status.textContent = '登録が完了しました。認証を続けます。';
                form.submit();
                return;
            }
        } catch (error) {
            status.textContent = '登録状態を確認しています…';
        }
        await pause(1000);
        poll();
    }

    poll();
})();