class PhishingSimulator {
    constructor() {
        this.score = 0;
        this.detected = 0;
        this.missed = 0;
        this.total = 0;
        this.currentScenario = null;
        
        this.scenarios = {
            bank: {
                name: 'Bank Alert',
                type: 'phishing',
                from: 'security@chase-bank.secure.com',
                subject: '⚠️ URGENT: Unauthorized Transaction',
                body: `
                    <p>Dear Customer,</p>
                    <p>We detected suspicious activity on your account.</p>
                    <div class="red-flag">
                        ⚠️ <strong>Red Flags:</strong>
                        <ul>
                            <li>Suspicious sender (chase-bank.secure.com)</li>
                            <li>Urgent language creates panic</li>
                            <li>Generic greeting</li>
                        </ul>
                    </div>
                    <p><a href="#" class="email-link" onclick="simulator.analyzeLink(this, 'malicious')">Click here to verify</a></p>
                `,
                explanation: {
                    type: 'phishing',
                    red_flags: [
                        'Fake domain: chase-bank.secure.com (not chase.com)',
                        'Urgent language to make you act without thinking',
                        'Generic "Dear Customer" instead of your name'
                    ],
                    safe_actions: [
                        'Don\'t click the link',
                        'Go directly to the bank website',
                        'Contact your bank using verified phone number'
                    ]
                }
            },
            social: {
                name: 'Social Media',
                type: 'phishing',
                from: 'security@faceb00k-login.com',
                subject: '🔒 Security Alert: New Login',
                body: `
                    <p>Hi there!</p>
                    <p>We noticed a login from Moscow, Russia.</p>
                    <div class="red-flag">
                        ⚠️ <strong>Red Flags:</strong>
                        <ul>
                            <li>Fake domain (faceb00k with zeros)</li>
                            <li>Unsolicited security alert</li>
                        </ul>
                    </div>
                    <p><a href="#" class="email-link" onclick="simulator.analyzeLink(this, 'malicious')">Secure your account</a></p>
                `,
                explanation: {
                    type: 'phishing',
                    red_flags: [
                        '"faceb00k" uses zeros instead of "o"',
                        'Fake login page to steal credentials',
                        'Threat of account lock to pressure you'
                    ],
                    safe_actions: [
                        'Don\'t click the link',
                        'Go directly to the official website',
                        'Enable two-factor authentication'
                    ]
                }
            },
            work: {
                name: 'Work Email',
                type: 'legitimate',
                from: 'hr@company.com',
                subject: '📋 Benefits Review',
                body: `
                    <p>Hello Employee,</p>
                    <p>Please log in to update your benefits.</p>
                    <div class="safe-flag">
                        ✅ <strong>This looks legitimate:</strong>
                        <ul>
                            <li>Sender is from company domain</li>
                            <li>No urgent/threatening language</li>
                            <li>Professional tone</li>
                        </ul>
                    </div>
                    <p><a href="#" class="email-link" onclick="simulator.analyzeLink(this, 'safe')">https://hr.company.com/benefits</a></p>
                `,
                explanation: {
                    type: 'legitimate',
                    red_flags: [],
                    safe_actions: [
                        'From legitimate company domain',
                        'No urgent language',
                        'Standard company communication'
                    ]
                }
            },
            shopping: {
                name: 'Shopping Deal',
                type: 'phishing',
                from: 'order@amaz0n-support.com',
                subject: '🛒 Order Cancelled',
                body: `
                    <p>Your order has been CANCELLED.</p>
                    <div class="red-flag">
                        ⚠️ <strong>Red Flags:</strong>
                        <ul>
                            <li>"amaz0n" (zero instead of o)</li>
                            <li>Threat of lost order</li>
                            <li>Generic greeting</li>
                        </ul>
                    </div>
                    <p><a href="#" class="email-link" onclick="simulator.analyzeLink(this, 'malicious')">Update payment</a></p>
                `,
                explanation: {
                    type: 'phishing',
                    red_flags: [
                        'Fake domain "amaz0n-support.com"',
                        'Threat of order cancellation',
                        'Request for payment information'
                    ],
                    safe_actions: [
                        'Go directly to Amazon.com',
                        'Check your orders manually',
                        'Contact Amazon through official site'
                    ]
                }
            },
            tech: {
                name: 'Tech Support',
                type: 'phishing',
                from: 'support@outlook-servers.net',
                subject: '🔐 Account Security',
                body: `
                    <p>Verify your Microsoft account.</p>
                    <div class="red-flag">
                        ⚠️ <strong>Red Flags:</strong>
                        <ul>
                            <li>Not from microsoft.com</li>
                            <li>Threat of suspension</li>
                            <li>Generic greeting</li>
                        </ul>
                    </div>
                    <p><a href="#" class="email-link" onclick="simulator.analyzeLink(this, 'malicious')">Verify now</a></p>
                `,
                explanation: {
                    type: 'phishing',
                    red_flags: [
                        'Fake domain "outlook-servers.net"',
                        'Threat of account suspension',
                        'No specific details about the issue'
                    ],
                    safe_actions: [
                        'Go directly to Microsoft.com',
                        'Enable two-factor authentication',
                        'Microsoft never asks for password via email'
                    ]
                }
            }
        };
        
        this.init();
    }
    
    init() {
        document.querySelectorAll('.scenario-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const scenario = btn.dataset.scenario;
                if (scenario === 'random') {
                    this.loadRandomScenario();
                } else {
                    this.loadScenario(scenario);
                }
            });
        });
        
        document.getElementById('resetBtn').addEventListener('click', () => {
            this.resetProgress();
        });
        
        this.updateStats();
    }
    
    loadScenario(scenarioId) {
        const scenario = this.scenarios[scenarioId];
        if (!scenario) return;
        
        this.currentScenario = scenarioId;
        this.total++;
        
        const area = document.getElementById('simulationArea');
        area.className = 'simulation-area';
        
        area.innerHTML = `
            <div class="email-display">
                <div class="email-header">
                    <div class="email-from"><strong>From:</strong> ${scenario.from}</div>
                    <div class="email-subject">${scenario.subject}</div>
                </div>
                <div class="email-body">${scenario.body}</div>
                <div class="decision-buttons">
                    <button class="btn-phishing" onclick="simulator.makeDecision('phishing')">🎣 This is PHISHING</button>
                    <button class="btn-legitimate" onclick="simulator.makeDecision('legitimate')">✅ This is LEGITIMATE</button>
                </div>
                <div class="feedback" id="feedback"></div>
            </div>
        `;
        
        this.updateStats();
    }
    
    loadRandomScenario() {
        const keys = Object.keys(this.scenarios);
        const randomKey = keys[Math.floor(Math.random() * keys.length)];
        this.loadScenario(randomKey);
    }
    
    makeDecision(decision) {
        if (!this.currentScenario) return;
        
        const scenario = this.scenarios[this.currentScenario];
        const isCorrect = decision === scenario.type;
        const feedback = document.getElementById('feedback');
        
        if (isCorrect) {
            this.score += 10;
            if (decision === 'phishing') this.detected++;
            else this.missed++;
            
            feedback.className = 'feedback show correct';
            feedback.innerHTML = `
                <h4>✅ Correct!</h4>
                <p>You correctly identified this as ${decision === 'phishing' ? 'phishing' : 'legitimate'}.</p>
                ${this.getExplanation(scenario)}
            `;
        } else {
            if (decision === 'phishing') this.missed++;
            else this.detected++;
            
            feedback.className = 'feedback show incorrect';
            feedback.innerHTML = `
                <h4>❌ Not quite right.</h4>
                <p>This was actually ${scenario.type === 'phishing' ? 'PHISHING' : 'LEGITIMATE'}.</p>
                ${this.getExplanation(scenario)}
            `;
        }
        
        document.querySelectorAll('.decision-buttons button').forEach(btn => {
            btn.disabled = true;
            btn.style.opacity = '0.5';
        });
        
        this.updateStats();
    }
    
    getExplanation(scenario) {
        const exp = scenario.explanation;
        let html = '';
        
        if (exp.type === 'phishing') {
            html += `
                <div style="margin-top: 15px;">
                    <h4>🎣 Red Flags Detected:</h4>
                    <ul>${exp.red_flags.map(f => `<li>${f}</li>`).join('')}</ul>
                    <h4>✅ What To Do:</h4>
                    <ul>${exp.safe_actions.map(a => `<li>${a}</li>`).join('')}</ul>
                </div>
            `;
        } else {
            html += `
                <div style="margin-top: 15px;">
                    <h4>✅ Why This Is Safe:</h4>
                    <ul>${exp.safe_actions.map(a => `<li>${a}</li>`).join('')}</ul>
                </div>
            `;
        }
        
        return html;
    }
    
    analyzeLink(element, type) {
        event.preventDefault();
        const feedback = document.getElementById('feedback');
        
        if (type === 'malicious') {
            feedback.className = 'feedback show learning';
            feedback.innerHTML = `
                <h4>⚠️ SUSPICIOUS LINK!</h4>
                <p>This link leads to a fake website designed to steal your information.</p>
                <p>🔍 Always hover over links to see the real URL before clicking.</p>
            `;
        } else {
            feedback.className = 'feedback show learning';
            feedback.innerHTML = `
                <h4>✅ Safe Link</h4>
                <p>This link goes to a legitimate website.</p>
                <p>💡 Always verify the domain matches the official website.</p>
            `;
        }
    }
    
    updateStats() {
        document.getElementById('score').textContent = this.score;
        document.getElementById('detected').textContent = this.detected;
        document.getElementById('missed').textContent = this.missed;
        document.getElementById('total').textContent = this.total;
    }
    
    resetProgress() {
        this.score = 0;
        this.detected = 0;
        this.missed = 0;
        this.total = 0;
        this.currentScenario = null;
        
        const area = document.getElementById('simulationArea');
        area.className = 'simulation-area';
        area.innerHTML = `
            <div class="placeholder">
                <p>👆 Select a scenario above to start</p>
                <p class="hint">You'll see an email and decide if it's phishing or legitimate</p>
            </div>
        `;
        
        this.updateStats();
    }
}

const simulator = new PhishingSimulator();