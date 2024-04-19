<!--
 * This code is to be used exclusively in connection with ForgeRock’s software or services. 
 * ForgeRock only offers ForgeRock software or services to legal entities who have entered 
 * into a binding license agreement with ForgeRock. 
-->
# SecurID

A simple authentication node for ForgeRock's [Identity Platform][forgerock_platform] 7.3.0 and above. The **RSA SecurID** node lets you use the [RSA Cloud Authentication Service (RSA ID Plus)](https://community.rsa.com/s/article/Cloud-Authentication-Service-Overview-235ded8d) or [RSA Authentication Manager](https://community.rsa.com/s/article/How-RSA-Authentication-Manager-Protects-Your-Resources-f6d03a2f) from within an authentication journey on your Identity Cloud environment.


Copy the .jar file from the ../target directory into the ../web-container/webapps/openam/WEB-INF/lib directory where AM is deployed.  Restart the web container to pick up the new node.  The node will then appear in the authentication trees components palette.

This node lets users authenticate using their registered RSA authenticators, including:

* [SecurID OTP](https://community.rsa.com/s/article/Authentication-Methods-for-Cloud-Authentication-Service-Users-80e1a27a#RSA) (hardware and software tokens), including new PIN mode
* [SecurID Authenticate OTP](https://community.rsa.com/s/article/Authentication-Methods-for-Cloud-Authentication-Service-Users-80e1a27a#Tokenco)
* [Emergency Access Code](https://community.rsa.com/s/article/Authentication-Methods-for-Cloud-Authentication-Service-Users-80e1a27a#Emergenc)
* [Approve (Push Notifications)](https://community.rsa.com/s/article/Authentication-Methods-for-Cloud-Authentication-Service-Users-80e1a27a#Approve)
* [Device Biometrics](https://community.rsa.com/s/article/Authentication-Methods-for-Cloud-Authentication-Service-Users-80e1a27a#Device)
* [QR Code](https://community.rsa.com/s/article/Authentication-Methods-for-Cloud-Authentication-Service-Users-80e1a27a)
* [SMS OTP](https://community.rsa.com/s/article/Authentication-Methods-for-Cloud-Authentication-Service-Users-80e1a27a#SMS)
* [Voice OTP](https://community.rsa.com/s/article/Authentication-Methods-for-Cloud-Authentication-Service-Users-80e1a27a#Voice)


## Quick start with sample journeys

Identity Cloud provides sample journeys to help you understand the most common RSA SecurID use cases. To use the samples, download [the JSON files for sample journeys](https://github.com/ForgeRock/Rsa-SecurId-Auth-Tree-Nodes/tree/cloud-prep/sample) and import the downloaded sample journeys into your Identity Cloud environment.


### Dependencies

To use this node, you must:

* Enroll RSA authenticators. Refer to [RSA SecurID setup](https://backstage.forgerock.com/docs/auth-node-ref/latest/cloud/auth-node-rsa-securid.html) for more information.
* Ensure the username on the shared node state matches one of the following:
	* The username, alternate username, or email address of the user in the RSA Cloud Authentication.
	* The username in RSA Authentication Manager.

## RSA SecurID setup


The **RSA SecurID node** in Identity Cloud can be used with the RSA Cloud Authentication Service or RSA Authentication Manager. Depending on which integration you choose, the RSA setup differs slightly.

### Setup with RSA Cloud Authentication Service

<ol type="1">
  <li>Configure the following using the RSA Cloud Administration Console:</li>
    <ol type="a">
      	<li><strong>Assurance Levels:</strong> Refer to the <a href="https://community.securid.com/s/article/Configure-Assurance-Levels-cb0a8b18"> Configure Assurance Levels page in the RSA documentation</a>
</li>
      	<li><strong>Policies:</strong> Refer to the <a href="https://community.securid.com/s/article/Manage-Access-Policies-14b3a6b2">Manage Access Policies page in the RSA documentation</a> .

Note the policy name you will use when configuring the RSA SecurID node in your Identity Cloud journey.
       </li>
       <li><strong>Authentication API Keys:</strong> Refer to the <a href="https://community.securid.com/s/article/Manage-the-SecurID-Authentication-API-Keys-09a51852">Manage the SecurID API Keys in the RSA documentation</a> .

Note the SecurID Authentication API REST URL and Authentication API key you will use when configuring the RSA SecurID node in your Identity Cloud journey.
        </li>
        <li><strong>End users enroll their RSA authenticators:</strong> Refer to the [Manage My Page in the RSA documentation](https://community.rsa.com/s/article/Manage-My-Page-9410c3e9).</li>
        </ol>
  </li>
</ol>

### Setup with RSA Authentication Manager

<ol type="1">
   <li>Using the RSA Authentication Manager Security console, configure the following:</li>
   <ol type="a">
       <li>
        Go to <strong>Access > Authentication Agents > Add New</strong> and add a new access agent.

Note the Authentication Agent name. You will need this when configuring the RSA SecurID node in your Identity Cloud journey. For additional information, refer to the <a href="https://community.rsa.com/s/article/Add-an-Authentication-Agent-3e61c187">Add an Authentication Agent page in RSA documentation</a>.
       </li>
       <li>
        Go to <strong>Setup > System Settings > RSA SecurID Authentication API</strong>, and note the access key. You will use this key in the SecurID node configuration. For additional information, refer to the <a href="https://community.rsa.com/s/article/Configure-the-RSA-SecurID-Authentication-API-for-Authentication-Agents-b82a1744">Configure the RSA SecurID Authentication API for Authentication Agents page in the RSA documentation</a>.
       </li>
   </ol>
   <li>You’ll need the REST API URL for your RSA environment. Get the REST API URL from your RSA Authentication Manager administrator.</li>
</ol>


## RSA SecurID node implementation

Refer to the implementation details of <a href="https://backstage.forgerock.com/docs/auth-node-ref/latest/cloud/auth-node-rsa-securid.html">RSA SecurID node here</a>.


# RSA SecurID node

The <strong>RSA SecurID</strong> node lets users authenticate using their registered RSA authenticators.

## Compatibility

<table>
<colgroup>
<col>
<col>
</colgroup>
<thead>
<tr>
<th>Product</th>
<th>Compatible?</th>
</tr>
</thead>
<tbody>
<tr>
<td><p>ForgeRock Identity Cloud</p></td>
<td><p><span><i>✓</i></span></p></td>
</tr>
<tr>
<td><p>ForgeRock Access Management (self-managed)</p></td>
<td><p><span><i>✓</i></span></p></td>
</tr>
<tr>
<td><p>ForgeRock Identity Platform (self-managed)</p></td>
<td><p><span class="icon"><i class="fa fa-check" title="yes">✓</i></span></p></td>
</tr>
</tbody>
</table>


## Inputs


The <code>username</code> attribute must exist in the shared node state as an input to the node.

## Configuration

<table class="tableblock frame-all grid-all fit-content">
<colgroup>
<col>
<col>
</colgroup>
<thead>
<tr>
<th class="tableblock halign-left valign-top">Property</th>
<th class="tableblock halign-left valign-top">Usage</th>
</tr>
</thead>
<tbody>
<tr>
<td class="tableblock halign-left valign-top"><p class="tableblock"><span class="label">Base URL</span></p></td>
<td class="tableblock halign-left valign-top"><div class="content"><div class="paragraph">
<p>The RSA endpoint.</p>
</div>
<div class="ulist">
<ul>
<li>
<p>For connections to the RSA Cloud Authentication Service, such as
https://<span class="var">companyname</span>.auth.securid.com:443/mfa/v1_1</p>
</li>
<li>
<p>For connections through RSA Authentication Manager, such as
https://<span class="var">RSA.AM.server</span>:5555/mfa/v1_1</p>
</li>
</ul>
</div></div></td>
</tr>
<tr>
<td class="tableblock halign-left valign-top"><p class="tableblock"><span class="label">Client ID</span></p></td>
<td class="tableblock halign-left valign-top"><div class="content"><div class="paragraph">
<p>The name used by this node as the client ID for connecting to the RSA endpoint.
This can contain alphanumeric English characters only.</p>
</div>
<div class="ulist">
<ul>
<li>
<p>For connections to the RSA Cloud Authentication Service, this can be any
string. End users will see this value as part of push notification messages,
and administrators will see this as the application name in the <span class="label">User
Event Monitor</span> of the RSA Cloud Administration Console.</p>
<div class="paragraph">
<p>Example:  <span class="var">ForgeRock Login Journey</span>.</p>
</div>
</li>
<li>
<p>For connections to RSA Authentication Manager, this value must match an Authentication Agent name configured in the RSA Authentication Manager Security Console.</p>
<div class="paragraph">
<p>Example: <span class="var">MyAgentName</span></p>
</div>
</li>
</ul>
</div></div></td>
</tr>
<tr>
<td class="tableblock halign-left valign-top"><p class="tableblock"><span class="label">Assurance Policy ID</span></p></td>
<td class="tableblock halign-left valign-top"><div class="content"><div class="paragraph">
<p>The name of the RSA Cloud Authentication Service policy to use. This name can
contain alphanumeric English characters only. This name is required for
connections to RSA Authentication Manager only when RSA AM acts as a
proxy for connections to the cloud.</p>
</div>
<div class="paragraph">
<p>Example:  <span class="var">All Users Medium Assurance Level</span>.</p>
</div></div></td>
</tr>
<tr>
<td class="tableblock halign-left valign-top"><p class="tableblock"><span class="label">Client Key</span></p></td>
<td class="tableblock halign-left valign-top"><div class="content"><div class="paragraph">
<p>The API key for connecting to the RSA endpoint.</p>
</div>
<div class="ulist">
<ul>
<li>
<p>For the RSA Cloud Authentication Service, this value can be generated or
obtained using the RSA Cloud Administration Console, <span class="label">My Account &gt;
Company Settings &gt; Authentication API Keys</span>.</p>
</li>
<li>
<p>For RSA Authentication Manager, this value can be found in the RSA Security
Console, <span class="label">Setup &gt; System Settings &gt; RSA SecurID Authentication API
(Access Key)</span>.</p>
</li>
</ul>
</div></div></td>
</tr>
<tr>
<td class="tableblock halign-left valign-top"><p class="tableblock"><span class="label">Verify SSL</span></p></td>
<td class="tableblock halign-left valign-top"><p class="tableblock">A boolean to verify the SSL connection. It is enabled by default. If disabled,
the node ignores SSL/TLS errors, including hostname mismatch and certificates
signed by an unknown Certificate Authority, such as self-signed certificates.</p></td>
</tr>
<tr>
<td class="tableblock halign-left valign-top"><p class="tableblock"><span class="label">Prompt for MFA Choice</span></p></td>
<td class="tableblock halign-left valign-top"><div class="content"><div class="paragraph">
<p>The string to display to end users on the MFA selection input page.</p>
</div>
<div class="paragraph">
<p>Example:  <span class="var">Select your preferred Authentication Method</span>.</p>
</div></div></td>
</tr>
<tr>
<td class="tableblock halign-left valign-top"><p class="tableblock"><span class="label">Waiting Message</span></p></td>
<td class="tableblock halign-left valign-top"><div class="content"><div class="paragraph">
<p>The string to display to end users when a push notification has been sent to
the user’s registered device.</p>
</div>
<div class="paragraph">
<p>Example: <span class="var">Please check your registered mobile device for an authentication prompt</span>.</p>
</div></div></td>
</tr>
</tbody>
</table>

## Outputs

None

## Outcomes

<dl>
<dt class="hdlist1"><code>Success</code></dt>
<dd>
<p>The user completed the RSA authentication process and does not require any
further steps according to the <a href="https://docs.google.com/document/d/1CX7aCiME-NZFyUvd6ZL4uYG4WkVriwWr0vUFeiaB2bE/edit?pli=1#heading=h.w290uwxmmyof">RSA Assurance Policy</a> this node references.</p>
</dd>
<dt class="hdlist1"><code>Failure</code></dt>
<dd>
<p>The user has failed the RSA MFA authentication.</p>
</dd>
<dt class="hdlist1"><code>Not Enrolled</code></dt>
<dd>
<p>The user is not enrolled in any RSA authentication methods required by the
specified policy.</p>
</dd>
<dt class="hdlist1"><code>Cancel</code></dt>
<dd>
<p>The user pressed the cancel button.</p>
</dd>
<dt class="hdlist1"><code>Error</code></dt>
<dd>
<p>An error occurred. Refer to the 'Troubleshooting' section.</p>
</dd>
</dl>

## Troubleshooting

Review the log messages to find the reason for the error and address the issue appropriately.

## Limitations and known issues

<ul>
<li>
<p>The RSA SecurID node supports most RSA authentication methods;
however, the following RSA authentication methods are not supported:</p>
<div class="ulist">
<ul>
<li>
<p><strong><a href="https://community.rsa.com/s/article/Authentication-Methods-for-Cloud-Authentication-Service-Users-80e1a27a#FIDO">FIDO</a></strong>: Customers can consider
using the ForgeRock WebAuthn nodes as an alternative.</p>
</li>
<li>
<p><strong><a href="https://community.rsa.com/s/article/Authentication-Methods-for-Cloud-Authentication-Service-Users-80e1a27a#LDAP">LDAP Directory Password</a></strong> or <strong>RSA
Cloud Authentication Service password</strong>: Customers can consider using
ForgeRock Platform Password and Data Store Decision nodes, or Pass-through
Authentication nodes as alternatives.</p>
</li>
</ul>
</div>
</li>
<li>
<p>SecurID tokens are not supported in Next Tokencode mode.</p>
</li>
<li>
<p>RSA API returns multiple authentication options when only the New
PIN mode option should be returned. This situation occurs when all
these conditions are met:</p>
<div class="ulist">
<ul>
<li>
<p>The RSA SecurID node connects to the RSA Cloud Authentication Service
directly or through RSA Authentication Manager as a proxy.</p>
</li>
<li>
<p>The configured policy &amp; assurance level &amp; user-enrolled authenticators include
SecurID and other authentication methods.</p>
</li>
<li>
<p>The user selects the SecurID option, and their SecurID token is in new PIN mode.</p>
<div class="paragraph">
<p>Seeing multiple options can be confusing when <em>only</em> the New PIN option is
expected. The RSA team is aware of this RSA API behavior and is evaluating ways
to correct the behavior to ensure that the REST API returns only the SecurID new
PIN and passcode prompts.</p>
</div>
</li>
</ul>
</div>
</li>
<li>
<p>The RSA SecurID node only supports English characters for:</p>
<div class="ulist">
<ul>
<li>
<p>Client ID</p>
</li>
<li>
<p>Assurance Policy ID</p>
</li>
</ul>
</div>
</li>
</ul>

## Examples

<p>Identity Cloud provides <a href="https://github.com/ForgeRock/Rsa-SecurId-Auth-Tree-Nodes/tree/cloud-prep/sample">sample
journeys</a>. You can download the JSON file to understand and implement the most
common RSA SecurID use cases.</p>

This example journey highlights using the RSA SecurID node to authenticate users:

<img src="https://backstage.forgerock.com/docs/idcloud/latest/release-notes/_images/rsa-securid-journey.png"/>
