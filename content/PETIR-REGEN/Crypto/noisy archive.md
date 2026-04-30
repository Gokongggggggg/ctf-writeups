![[Pasted image 20260407075231.png]]

## Chall.py

``` python
from Crypto.Util.number import getPrime, bytes_to_long
import random
import hashlib

flag = b"PETIR{REDACTED}"

m = bytes_to_long(flag)
p_bits = max(512, m.bit_length() + 64)
p = getPrime(p_bits)

e = random.randint(1, p-1)
while e % 2 != 0: 
    e = random.randint(1, p-1)

k = 15 

coefficients = [pow(m, e, p)] + [random.randint(1, p-1) for _ in range(k-1)]

def f(x):
    return sum(c * pow(x, i, p) for i, c in enumerate(coefficients)) % p

N = 45
points = []
for i in range(1, N + 1):
    points.append((i, f(i)))

E = 14
error_indices = random.sample(range(N), E)
noisy_points = []

for i in range(N):
    x, y = points[i]
    if i in error_indices:
        noisy_points.append((x, random.randint(1, p-1)))
    else:
        noisy_points.append((x, y))

random.shuffle(noisy_points)

with open("output.txt", "w") as f_out:
    f_out.write("PETIR - archive export\n")
    f_out.write(f"p = {p}\n")
    f_out.write(f"k = {k}\n")
    f_out.write(f"e = {e}\n")
    f_out.write(f"shares = {noisy_points}\n")

    f_out.write("\n")
    f_out.write(f"build_id = '{build_id}'\n")
    f_out.write(f"session_nonce = {session_nonce}\n")
    f_out.write(f"noise_profile = {noise_profile}\n")
    f_out.write(f"share_digest = '{share_digest}'\n")
```

>[!note]- Explanation
>
> The `chall.py` script is the generator for the output.txt  
> Its job is to take the flag, hide it inside a polynomial, then deliberately corrupt some of the output points so you cannot recover the secret with normal interpolation directly.
>
> ---
>
> ## 1. Converting the flag into a number
>
> ```python
> m = bytes_to_long(flag)
> ```
>
> The flag starts as bytes:
>
> ```python
> flag = b"PETIR{REDACTED}"
> ```
>
> but math over finite fields works with integers, not raw byte strings.  
> So the script converts the flag into a big integer `m`.
>
> You can think of this like:
>
> - original form = text / bytes
> - math form = one large number
>
> ---
>
> ## 2. Choosing a prime modulus `p`
>
> ```python
> p_bits = max(512, m.bit_length() + 64)
> p = getPrime(p_bits)
> ```
>
> This creates a prime number `p` that is large enough to safely contain the flag value.
>
> The idea:
>
> - `m.bit_length()` = how many bits are needed to store the flag integer
> - `+ 64` = extra safety margin
> - `max(512, ...)` = ensure the modulus is at least 512 bits
>
> Why is this important?
>
> Because all computations happen modulo `p`.
>
> If `p` were too small, values would “wrap around” too aggressively and the hidden value could become harder or impossible to interpret cleanly.
>
> So this part basically says:
>
> > “Pick a sufficiently large prime field so the secret can live safely inside it.”
>
> ---
>
> ## 3. Creating the exponent trap
>
> ```python
> e = random.randint(1, p-1)
> while e % 2 != 0: 
>     e = random.randint(1, p-1)
> ```
>
> The challenge chooses a random exponent `e`, but forces it to be **even**.
>
> This matters because the secret is not stored directly.  
> Instead, the script stores:
>
> ```python
> pow(m, e, p)
> ```
>
> which is:
>
> $$
> m^e \bmod p
> $$
>
> At first glance this looks like an extra encryption layer.
>
> The reason this is annoying for the solver is that when `e` is even, modular root extraction becomes less straightforward.  
> In modular arithmetic, an even power can have multiple possible roots, so after recovering `m^e mod p`, you may still need to determine which root corresponds to the real flag.
>
> So this is basically a trap layer:
>
> - the polynomial does **not** hide `m`
> - it hides `m^e mod p`
> - and because `e` is even, recovering `m` later can produce multiple candidates
>
> ---
>
> ## 4. Hiding the secret inside a polynomial
>
> ```python
> k = 15
> coefficients = [pow(m, e, p)] + [random.randint(1, p-1) for _ in range(k-1)]
> ```
>
> Here the script builds a polynomial over the field modulo `p`.
>
> Since `k = 15`, the polynomial has `15` coefficients:
>
> - `c0 = m^e mod p`
> - `c1, c2, ..., c14` are random
>
> So the polynomial looks like:
>
> $$
> f(x) = c_0 + c_1x + c_2x^2 + \cdots + c_{14}x^{14} \pmod p
> $$
>
> where:
>
> $$
> c_0 = m^e \pmod p
> $$
>
> This means the secret is hidden in the **constant term** (intercept) of the polynomial.
>
> This is very similar to **Shamir Secret Sharing** style logic:
>
> - the secret is stored in the constant term
> - the rest of the coefficients are random
> - enough correct points let you reconstruct the polynomial
>
> Because the degree is `14`, you need at least `15` correct points to uniquely recover it.
>
> ---
>
> ## 5. Evaluating the polynomial into shares
>
> ```python
> def f(x):
>     return sum(c * pow(x, i, p) for i, c in enumerate(coefficients)) % p
> ```
>
> This function evaluates the polynomial at some `x`.
>
> Then the script generates `45` points:
>
> ```python
> N = 45
> points = []
> for i in range(1, N + 1):
>     points.append((i, f(i)))
> ```
>
> So now we have:
>
> $$
> (1, f(1)), (2, f(2)), \dots, (45, f(45))
> $$
>
> These are the polynomial shares.
>
> If all of them were correct, then solving would be easy:
>
> - take any 15 correct points
> - interpolate the degree-14 polynomial
> - recover `c0 = m^e mod p`
>
> But the script is not finished yet.
>
> ---
>
> ## 6. Injecting noise into the dataset
>
> ```python
> E = 14
> error_indices = random.sample(range(N), E)
> noisy_points = []
> ```
>
> Out of the `45` shares, the script chooses `14` random positions to corrupt.
>
> Then:
>
> ```python
> for i in range(N):
>     x, y = points[i]
>     if i in error_indices:
>         noisy_points.append((x, random.randint(1, p-1)))
>     else:
>         noisy_points.append((x, y))
> ```
>
> This means:
>
> - `31` points are honest
> - `14` points are fake
>
> The fake points keep the same `x`, but replace the real `y` with random garbage.
>
> So visually:
>
> - honest points lie on the same polynomial
> - fake points are just random noise
>
> This is the main obstacle of the challenge.
>
> Normal interpolation assumes all given points are valid.  
> But here, some points are outright lies.
>
> So if you feed all points directly into interpolation, the result will be wrong.
>
> ---
>
> ## 7. Shuffling to hide which shares are fake
>
> ```python
> random.shuffle(noisy_points)
> ```
>
> The points are shuffled before being written out.
>
> This removes any ordering clue.
>
> So you cannot rely on:
>
> - early points being correct
> - corrupted points appearing at the end
> - index patterns
>
> All shares are mixed together, and you must identify the honest subset mathematically.
>
> ---
>
> ## 8. Writing the challenge output
>
> ```python
> with open("output.txt", "w") as f_out:
>     f_out.write("PETIR - archive export\n")
>     f_out.write(f"p = {p}\n")
>     f_out.write(f"k = {k}\n")
>     f_out.write(f"e = {e}\n")
>     f_out.write(f"shares = {noisy_points}\n")
> ```
>
> The important values exported are:
>
> - `p` → the finite field modulus
> - `k = 15` → tells you the polynomial degree is `14`
> - `e` → the exponent used on the flag
> - `shares` → the shuffled noisy points
>
> The rest:
>
> ```python
> f_out.write(f"build_id = '{build_id}'\n")
> f_out.write(f"session_nonce = {session_nonce}\n")
> f_out.write(f"noise_profile = {noise_profile}\n")
> f_out.write(f"share_digest = '{share_digest}'\n")
> ```
>
> are likely extra metadata / flavor / distraction unless they are used elsewhere in the challenge.
>
> The core math-relevant data is still:
>
> - `p`
> - `k`
> - `e`
> - noisy shares
>

## output.txt

``` txt
┌──(gokong㉿kali)-[~/Documents/petir-regen/cry/noisy_archive]
└─$ cat output.txt                            
PETIR - archive export
p = 3920806865293695682503769122241517152130038977971701698596273124465990242332956185162611128106555262044475528124060752397436908247027837522970358226663559879529044196756053816822752033235184351868427639220100295498224253623433617243179822334691422181480207626057562875356674880383721647384080456568436807314430858022846138481
k = 15
e = 525820642660056926896053797275845806184692207657767820680174206050189906207830717780759849881083015816186408787344673004784016798929419654221311246090092517231374696196320295300352417787613910336963004062863168340814016180167550097797550749331615017025189724740714472178116733827281079245030030246746469650414993468099160130
shares = [(23, 3536131546684919518178977362425353316604055589297600532516889211843613314215426393332731126500733638030078951978957132931293719875095052263587270972223082494866725930698344341827794698170013946304983127114730229064607497437364845779065708304860601428539160324171815125183837315355303435268993372632658473400301464603648175689), (34, 3248210488649061714109881767639531278671305839047469828488289243633030790893355984679335247514023164679215895430702248097525846055620303325906801854372284163697317026927686145596909033688862122165567512674475714319696935756839587256241124956500755389918135063621198303252477183150135614969927848366029111621679186105759193316), (40, 232868903048372959980426661236492184553511393152818588325693683434160605679982528065899097864998741696853950059572241135267434087073967358087488535843826749640350378316888371789206560322303464895878954218156249362680906551668870770318186608992368087339409022938977473710040502101337348682313607351200566754430588523278358591), (14, 1204271213769168756204048733314104559771488254001423703343781727585319855284367022788849967932824879388193155279582896690816297347489974451114233236815895664255623178500935423214851588616674605885212880218331397801713733569100858085145903799078693172827719865323773067419049318625599737445195861475403287996390525825102800658), (30, 3461025533998821127288363547280488991300253638768337857554446479930867957685565910208383088872051361484081549117506892141814687753244132669111128281264026702438346690100705818625665615571177027969754104210179292218794639354504543062214167375248631293411339738156003420737414949973715040721043347323470710659362154255447071100), (12, 2638271050032948494998462480814029622217926312201718659583932407676437554803625472079558036446883461978305344594589876255787048151122370551874644746623946741660985653965766642331871450640045756182500811658806888791553437325745185539999069184046520801448137151126249930353443672115827810351479692119671495530875322520550746876), (39, 1301291184156758285439289976193324802806342878022013378101173189054275923178284608362357178639876494297704954451968953332690394929921428371289197437408963803936651545364866708273849460427041878551935550657844155260005600036859872319592453743482095710995641903180440403576137310750434093741910244307625607194933248028944062477), (3, 302094674071220808329094054983746303538887639962418166353004603579871721053054371126153780950856528249577225247908034866714510785518746009914274959807834460655434574337670812903518337071226229081112661184391730529027140402225014722468772326075515188817006755008915293544015918997474593392695199232913794657261112341465248540), (27, 962260917575343685864930820647259095168490266542963989533858671461592266955080362851871268643365900788930245286439191327685743504958248066913664116203379321157826085049195619003115231664202863895162189346570248877431084522240145964940915495547803945055145852437525360187195496514202824297926658167324267648019513888789562334), (11, 3883068782286660577591849236479939287698488353050818578374410306350374017087206145942460729821873893450630830096955434192560828577132012383957299208768822292785034181652855356563699688779846980258548816659252487485829946785865439815890943908631833304133797130116404258527439561403890153892678919209376365434061349480061908183), (24, 3133894220837746724540308092665956263148104145649749122618069033529732063107515771056063998673972748870331765000045539253997621793606962678336217221802892213506410069112013603232224654108935135967731603530129339801193824374147984073479649723224976655988505026374833892599416231877916043056251300042834312151992829672531907935), (28, 3643040035007245815764336117711486729293782925789466131689715571587059070015600388614758448429708863905324484625833975218982297771518753562681866728963789364773699122042888259674672944535316630253912724680403591482568454979902214883792094052909354443465041929268228479186017430137404592071515340835652373896885019642604635588), (31, 2104378400734896416525606292631589592690219190414745691768550204701353959954076062049671921459659189188091682778201797296980821427979576983841361051357497410147709775306943852060305715955441006252781644884187679200412715577862413617469344368887278584223710307322177840046707316118945109951044421544948952160578905641845637018), (15, 630699990632154130576467672113483044185760822280306712903245056041472446327272476993645747849059153044413891883005020801771449216156352261992914756081443864745849428302917506554299553444039459100557661061485769614142987616037191581843015913265111777488030617746997532791562775506520652633955090818269212453266020271471860182), (42, 567976110472257857609400357791446647529785324122121741224502309619818470310324374340406003735493369401867029119547599249656587058041484610424030508378236408675558715919487548987423789234725504947461881384929041680546212315108704562025964346440615501919424622410750003311776201462280549619592669736871469296076851054244897273), (13, 990030630842913290937729728709267666041041886054896066813405308218790247298890145174162527982405418244808671915221497762584980663581982010513951933311117327921182607707302973689227854894555402824436024956587869250748617849297188180434917802809568755961591184803558353618173746599090712614372671875389400743098553719198261133), (35, 1064177031927659294816756059410094237930918172836481493792215172572642172447056295042671691550025610287246407325013440348767110092720530981939414726727405277250830821617496536920306417256022048287525158990767854205032465007648869570724480564053010779798220361577125791177980195313903120710573041930506712512685750973005902698), (1, 2112280230549415425764648927688948776223123039838086377787220528541763507747689544363932405861666131437466614961287505115331109051559463306436221744577046514861470822285328064447568245533776651349431273792175548131902966345037741754660639089024562907554372589788697647889151060771774378190873347243787971994654282036171300257), (38, 2810496968583931812892360220538600240579676503266443055130991247973019233406743008349751175651898188948983703947620249365742104113058311758363003597403114998190166216922705988574364792831975417667546798718067287007269763634643472373666761263745901595309008936355385343081027697424071635997694916961358294925009260289696899283), (10, 3271627967683331977109535248372678134788026109354380801631029034923690230550981545438123529263708663337298228326431905818443005290950862123210948758936322378966564421747520458002748686621073454961891826499986262769692224972128717400887344148646569208526648087749769813529308016184776882351473055121599470746333516124992106424), (25, 868799041636108362304461321060400627035845058336353049928665591168824726265170845597174439137286423467307411608017039099558368942484869365084915477623469693909149227035100642463434122801377874310534143320869655684963012320977706186497127721642913630525864098997782177396595170515691559108141026713466970532483901319050187068), (33, 747717420426789477514740478529581798795407172320751401164333961872955303747138925070759992936759974816630784146967453373276092258527455019220542213682986607703686966579480061674211503106417347699512665316872198151833580884972114097260940336420636575961165240663501864498036866537868715097552261955657000094213312264640852255), (26, 2992568201625161130714552412746608278918642011813587438127901106036601147939009147006942501254485105684127234192218787148411176491396522483535201500653144371825520280900768344133669934220680725457403201906540228945324568817447501785431227914832788346971338725397943635038535560571755947863600316824262583046221589469793099329), (37, 1781681735524923370010403044170293755491885839944205480892140180661755425950861591765171478085120772568665260256017295519951585924939222360533135317250991911706489083198667442569859186472608432588326151807364147319197574442029526205444268714397448336448952559751619564245590849040216271967964929145781505839576794040193168215), (45, 803396382840542504169620591608165359960093777050375629468024024111645163374279229259034324658215664186040691979728255258985689066112300891880389935647204068665519771128205784135711540596680684477232560506417376921144287779235011362604560603554684442373308000825942683908595417188552369210388032084982715226188063307511470785), (4, 1079288132413375589226893102821885514056907591049750077233426022412626149170116396575956611161662174466588530022945794279070557682621921518372751204990374349005409545065833591649729364900173446341323891618963462725643180508319521830240352561926692336746379353958135319762319233750987115461483546376703411766870908451497217799), (17, 2036563746331424332948388280582949410637592503195452469667913974340053022356666146248838503754586116319479086964468154037043572679328313303855415933477011033010198363526660313556659255892268647939994850774208489304068167895281527226323935253655090483319474856975357470375615688579304607322812837400751536637630773655246819184), (36, 2552960478120609155338534588327264219452878784110349032922420823576554360881495563993112479793835658488673401176595548121733507203528496380886198039252299246863618143142968187049304341582352006633519094797181397205350014193087214074290366491805332502841584703036860744595387366494591882425576345839788039646062324640156645643), (29, 291974852070141763977257350539088171421878339342496607502214646255443291387832568787166901900451336960508061602942696813401645600490329019555788341843134750393981342598679812728298043070582220856645864206837810874839412394050229544708917173522365068725937974028938974747422155077067853394763038835197135161088842911395798212), (41, 1762050302492816606299530735587882065609720905956885424495740359894445713131199321893501660621430787093528606485344323548012104131116529606977587319013548885241591853647248066055632418047657395031717364443690861537336813836069158207961207814088647399374008402428444411022838950967026175779484556818566822693051825836346893545), (8, 3018336588253379739620706516005709676890194114049358715170464901901967166773033943545798703990288086474531737952865036216236594411402179962018782413077208792622406118561654412670390455897706345318976430160605607991707246327817997874532393071325388805616281998758600563273012028079826164627044983408861455467422636772480609486), (2, 3683362433802630870825703740979348042431898611394500655968566653257239121971255065595041978416635960030528358094770217512574326693642323071031172316506406709263303240001180983769214360189968204548940397595775105409302571294436244085582089037349159541622494161434410989796026521455291904836628246225372093057261386394657597902), (22, 3520371043731809479736071778783539537786817722886596300228252403914570884339284010698190927457510190959901411039977653298382247556356089498060308200201135726804240912865872605660006714648677252374372485648734955194743172051700905299524142977473557191354337640737189761297518994751026869530592444175487504010823618774963845354), (6, 1418974525978842332602037904955203657034047007363162549218269630466780176165313231848118087628226549763000140401982969445067123724118225372824186624696660938411310955761881255074463607340887273630295851381101133030245592309729282105161926844751563405311008985663734098668239866883872465993679322219873797894955289980190640214), (5, 1806528259686199148643265020787034936706769857849183459015366288509102549715397352264862840651320137759332951957438740564077860571523870184548990957671952294752373399955991267854485818432560057067128079266137304024502776743951370234530025879855519349155767082407908424856640843150289999075659450766207656379963918018775143776), (21, 1083924564063875265460596773922942974589266721904876774424607884362312668795350868155060372864265559289370192338223664053618330540822370902061575080032826155832602659052367070469245750700110025793849681712045785458341896570705304184991543861754846158061284533536593689149016737793766003237971700789656082322635344871589953040), (9, 1242296734639501893196387681791994939653005642030262367874656209692533183519388075916384967857232230981373839892834298938866781575612832697649304752267767359331799538671054763146214773896843730768498920048503272797047968107981613324825152026721723203023329110530532382325255545370742913940947488783551881507705388492111431934), (20, 3304496895590107055866227481753620828810903047425409447438814752567998313693620020305152655279974919235868761968522334203562947447491537331101648192407757060483987830674236157664059362498695733602710960135392821377127141410462369189939600560299801955672966860405198786600875362408900463039094235950639564501013027666986188053), (32, 1274328872350003257042800713778431830096527999656104043210990163144666775582925091083573469830863252144615830945465779015948557462911113063084706345097405965027601095481803827590265458562412370961509479935875573043846537232015534399222775321226618917442054646911053631997712853275456474096226516918188728845285342128506356483), (43, 3505704965503254509288784205416815035809456338637598509281343645094928078723307955748484334305233960231999413621985383250769187582601293307988792452486023965772689762835914207063362033388179758101452895179177512805214789169120724548474592411057385917755911471589196545640245038531494503762503555807913279215430491418575068696), (16, 3660650821121378931980225383663520859394160212478141549562712158329545869043503557686539370849294398278649175466109566243071880723939632708587115937966715574158467628207908932451649976542255975620690881471258261503445667824738274062926011557928273593024999441437257651475683531016810803057718209759265232994018108127532021423), (19, 1354623945334836043519473390583275463984827089221362566965895577550018643268358812622856873708909137444036060888287386029369423181299435788344438987301998842179109797278746177437954876612884723963503561523498794212386065002837903668069931562570880051461399938019451576887026654018621243465287929082977464119384907355631279459), (18, 1933182711409899253962487758762715289090922555939686531505758022098239630019616756623449349101947490833586479630458115041537768325309473522256003128718454324155107249549171020762786994525249814751929390402854748306307836344776936209345030723965300372805759920576773750516486349782621945858749803110294665442617900323673217014), (44, 3190515103837466052565755314251282666920972261195862146530482452080777350815468440805975117273847514284957610096862516251122250045579862356139910533390491198001957225887200100315403565519577918352434910291984181546030416980837763781256061746349283010385797125982407353802221073200956019347672348887969044826938724884919902421), (7, 2859524017267674164831778361540234925866157933666723547165269405482330478725857429981459812397251280474110869343832912442051994567709098478288365772630159353319163565912635013050236295148384670306281743955011922944264209876581708294841380665636822420165082787664220096134329836283549254156799366621850539267466588888712647210)]

build_id = '7e6a6cd803cbb54c'
session_nonce = 8721551771410443045
noise_profile = {'mode': 'mixed-telemetry', 'tag': 'PETIR-REGEN', 'shuffle': True}

```

>[!note]- Output we are given
>
> From `output.txt`, we obtain several important parameters needed for the recovery process:
>
> - `p` → the prime modulus, which defines the finite field where all polynomial operations take place
> - `k = 15` → this means the polynomial has degree `14`, so we need at least `15` valid points to reconstruct it
> - `e` → the exponent used to store the secret as `m^e mod p`
> - `shares` → the list of `(x, y)` points obtained from evaluating the polynomial, but mixed with some fake points
>
> Meanwhile, fields such as:
>
> - `build_id`
> - `session_nonce`
> - `noise_profile`
> - `share_digest`
>
> look more like extra metadata / distraction, and are not part of the core recovery process.
>
> So from this file, we already have all the main ingredients needed to solve the challenge: the field modulus, the polynomial degree, the exponent, and the list of noisy shares.
>
> At this point, we already understand how this data was generated.  
> **Now the next step is to recover the correct polynomial from the noisy shares, extract its constant term, and then recover the flag.**

## Solver.py

``` python
#!/usr/bin/env python3
import re
import random
import base64
from math import gcd

# =========================================================
# Helpers
# =========================================================

def get_int(label, text):
    match = re.search(rf"{label} = (\d+)", text)
    if match:
        return int(match.group(1))
    return None

def long_to_bytes(n):
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

def is_probably_base64(blob: bytes) -> bool:
    if not blob or len(blob) % 4 != 0:
        return False
    return re.fullmatch(rb"[A-Za-z0-9+/=]+\Z", blob) is not None

def peel_base64_all(blob: bytes):
    """
    Repeatedly decode base64 until it no longer works.
    Returns the full decoding chain.
    """
    chain = [blob]
    cur = blob
    seen = {blob}

    while True:
        if not is_probably_base64(cur):
            break
        try:
            nxt = base64.b64decode(cur, validate=True)
        except Exception:
            break

        if not nxt or nxt in seen:
            break

        chain.append(nxt)
        seen.add(nxt)
        cur = nxt

    return chain

def modInverse(a, m):
    return pow(a, -1, m)

# =========================================================
# Modular linear algebra
# =========================================================

def gaussian_elimination(mat, vec, p):
    n = len(mat)

    for i in range(n):
        pivot_idx = i
        while pivot_idx < n and mat[pivot_idx][i] % p == 0:
            pivot_idx += 1
        if pivot_idx == n:
            return None

        mat[i], mat[pivot_idx] = mat[pivot_idx], mat[i]
        vec[i], vec[pivot_idx] = vec[pivot_idx], vec[i]

        inv = modInverse(mat[i][i], p)

        for j in range(i, n):
            mat[i][j] = (mat[i][j] * inv) % p
        vec[i] = (vec[i] * inv) % p

        for j in range(i + 1, n):
            factor = mat[j][i] % p
            if factor == 0:
                continue
            for l in range(i, n):
                mat[j][l] = (mat[j][l] - factor * mat[i][l]) % p
            vec[j] = (vec[j] - factor * vec[i]) % p

    x = [0] * n
    for i in range(n - 1, -1, -1):
        s = sum(mat[i][j] * x[j] for j in range(i + 1, n)) % p
        x[i] = (vec[i] - s) % p
    return x

def get_coeffs(subset, k, p):
    mat = []
    vec = []
    for x, y in subset:
        row = [pow(x, i, p) for i in range(k)]
        mat.append(row)
        vec.append(y % p)
    return gaussian_elimination(mat, vec, p)

def eval_poly(coeffs, x, p):
    return sum(c * pow(x, i, p) for i, c in enumerate(coeffs)) % p

# =========================================================
# Root solving helpers
# =========================================================

def nth_root_s1(c, n, p):
    """
    One n-th root when n is prime and n || p-1
    """
    t = (p - 1) // n
    k_prime = (-modInverse(t, n)) % n
    Q = (t * k_prime + 1) // n
    return pow(c, Q, p)

def square_root(c, p):
    """
    Tonelli-Shanks
    """
    if c == 0:
        return 0

    if pow(c, (p - 1) // 2, p) != 1:
        return None

    s = 0
    q = p - 1
    while q % 2 == 0:
        q //= 2
        s += 1

    if s == 1:
        return pow(c, (p + 1) // 4, p)

    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    c_val = pow(z, q, p)
    t = pow(c, q, p)
    m = s
    r = pow(c, (q + 1) // 2, p)

    while t != 1:
        tt = t
        i = 0
        for i in range(1, m):
            tt = pow(tt, 2, p)
            if tt == 1:
                break

        b = pow(c_val, 2 ** (m - i - 1), p)
        m = i
        c_val = pow(b, 2, p)
        t = (t * c_val) % p
        r = (r * b) % p

    return r

def element_order(a, p):
    if pow(a, 70, p) != 1:
        return None

    ord_candidate = 70
    for q in [2, 5, 7]:
        while ord_candidate % q == 0 and pow(a, ord_candidate // q, p) == 1:
            ord_candidate //= q
    return ord_candidate

def get_all_70th_roots_of_unity(p):
    while True:
        g = random.randint(2, p - 2)
        u = pow(g, (p - 1) // 70, p)

        if u == 1:
            continue

        ord_u = element_order(u, p)
        if ord_u == 70:
            roots = []
            cur = 1
            for _ in range(70):
                roots.append(cur)
                cur = (cur * u) % p
            return roots

# =========================================================
# Candidate analysis
# =========================================================

def candidate_score(raw: bytes, chain):
    score = 0
    final = chain[-1]

    for item in chain:
        if b"PETIR{" in item:
            score += 1000
        if b"PETIR" in item:
            score += 300
        if b"flag" in item.lower():
            score += 150

    if len(chain) > 1:
        score += 50 * (len(chain) - 1)

    if all(32 <= b < 127 or b in (9, 10, 13) for b in final):
        score += 100

    if b"{" in final and b"}" in final:
        score += 200

    return score

def try_format_flag(final_bytes: bytes) -> str | None:
    """
    If final bytes already contain PETIR{...}, return that.
    Otherwise if it looks like the inner flag content, wrap it.
    """
    try:
        text = final_bytes.decode("utf-8", errors="ignore").strip()
    except Exception:
        return None

    m = re.search(r"PETIR\{.*?\}", text)
    if m:
        return m.group(0)

    # if it looks like inner content, wrap it
    if text and all(32 <= ord(ch) < 127 for ch in text):
        if "{" not in text and "}" not in text:
            return f"PETIR{{{text}}}"

    return None

# =========================================================
# Main solve
# =========================================================

def main():
    with open("output.txt", "r") as f:
        content = f.read()

    p = get_int("p", content)
    k = get_int("k", content)
    e = get_int("e", content)

    shares_match = re.search(r"shares = (\[.*\])", content, re.S)
    shares = eval(shares_match.group(1))

    print(f"[+] p = {p}")
    print(f"[+] k = {k}")
    print(f"[+] e = {e}")
    print(f"[+] total shares = {len(shares)}")

    # -----------------------------------------------------
    # Stage 1: recover polynomial using random subsets
    # -----------------------------------------------------
    print("[*] Recovering polynomial from noisy shares...")

    coeffs = None
    best_count = 0

    for attempt in range(10000):
        subset = random.sample(shares, k)
        cur = get_coeffs(subset, k, p)
        if cur is None:
            continue

        count = 0
        for x, y in shares:
            if eval_poly(cur, x, p) == y % p:
                count += 1

        if count > best_count:
            best_count = count
            print(f"[+] New best fit: {best_count}/45 on attempt {attempt + 1}")

        if count >= 31:
            coeffs = cur
            print(f"[+] Found valid polynomial! Passes through {count} points.")
            break

    if coeffs is None:
        print("[-] Failed to recover polynomial.")
        return

    C = coeffs[0]
    print(f"[+] Recovered constant term C = m^e mod p")
    print(f"[+] C = {C}")

    # -----------------------------------------------------
    # Stage 2: reduce huge e-th root problem
    # -----------------------------------------------------
    print("[*] Reducing the huge root problem...")

    e0 = e % (p - 1)
    d = gcd(e0, p - 1)
    print(f"[+] d = gcd(e, p-1) = {d}")

    k_red = e0 // d
    M = (p - 1) // d
    print(f"[+] gcd(k_red, M) = {gcd(k_red, M)}")

    k_inv = modInverse(k_red, M)
    C_prime = pow(C, k_inv, p)

    print(f"[+] Reduced equation: m^{d} = C_prime (mod p)")
    print(f"[+] C_prime = {C_prime}")

    if d != 70:
        print(f"[!] Warning: expected d = 70, but got d = {d}")
        print("[!] This script is tailored for the observed challenge instance.")
        return

    # -----------------------------------------------------
    # Stage 3: solve m^70 = C_prime
    # -----------------------------------------------------
    print("[*] Solving m^70 = C_prime ...")

    r7 = nth_root_s1(C_prime, 7, p)
    print(f"[+] One 7-th root found")

    r35 = nth_root_s1(r7, 5, p)
    print(f"[+] One 35-th root found")

    r70 = square_root(r35, p)
    if r70 is None:
        print("[-] Failed to find square root in final step.")
        return

    print(f"[+] One 70-th root found")

    # -----------------------------------------------------
    # Stage 4: enumerate all 70 roots
    # -----------------------------------------------------
    print("[*] Enumerating all 70 candidate roots...")

    roots_of_unity = get_all_70th_roots_of_unity(p)
    all_roots = [(r70 * u) % p for u in roots_of_unity]

    print(f"[+] Total candidate roots = {len(all_roots)}")

    # -----------------------------------------------------
    # Stage 5: analyze candidates, but print final hits at bottom
    # -----------------------------------------------------
    print("[*] Analyzing candidates...")

    interesting = []

    for idx, root in enumerate(all_roots):
        raw = long_to_bytes(root)
        chain = peel_base64_all(raw)
        final = chain[-1]
        score = candidate_score(raw, chain)
        flag_text = try_format_flag(final)

        # Keep only interesting ones
        if score > 0 or flag_text is not None:
            interesting.append({
                "idx": idx,
                "raw": raw,
                "chain": chain,
                "final": final,
                "score": score,
                "flag_text": flag_text,
            })

    interesting.sort(key=lambda x: x["score"], reverse=True)

    print(f"[+] Interesting candidates kept: {len(interesting)}")

    # Optional preview of top few
    preview = min(5, len(interesting))
    for item in interesting[:preview]:
        print(f"\n[preview] Candidate #{item['idx']} | score={item['score']}")
        print(f"  raw   = {item['raw']!r}")
        if len(item["chain"]) > 1:
            print(f"  final = {item['final']!r}")

    # -----------------------------------------------------
    # Final output at the bottom
    # -----------------------------------------------------
    print("\n" + "=" * 70)
    print("[FINAL RESULTS]")
    print("=" * 70)

    found_flags = []

    for item in interesting:
        if item["flag_text"] is not None:
            found_flags.append(item)

    if found_flags:
        for item in found_flags:
            print(f"\nCandidate #{item['idx']}")
            print(f"Raw bytes      : {item['raw']!r}")
            print("Decode chain   :")
            for i, step in enumerate(item["chain"]):
                print(f"  [{i}] {step!r}")
            print(f"Recovered flag : {item['flag_text']}")
    else:
        print("No direct final PETIR{...} found.")
        print("Top decoded candidates:")
        for item in interesting[:10]:
            print(f"\nCandidate #{item['idx']} | score={item['score']}")
            print(f"Raw bytes    : {item['raw']!r}")
            print("Decode chain :")
            for i, step in enumerate(item["chain"]):
                print(f"  [{i}] {step!r}")

if __name__ == "__main__":
    main()
```

>[!note]- Section 1 — Reading the challenge data
>
> The solver begins by opening `output.txt` and extracting the important parameters:
>
> ```python
> p = get_int("p", content)
> k = get_int("k", content)
> e = get_int("e", content)
>
> shares_match = re.search(r"shares = (\[.*\])", content, re.S)
> shares = eval(shares_match.group(1))
> ```
>
> These values are the core inputs of the challenge:
>
> - `p` is the prime modulus
> - `k = 15` means the hidden polynomial has degree `14`
> - `e` is the exponent used to hide the message
> - `shares` is the shuffled list of noisy points
>
> So before solving anything, this section just loads the full challenge state into memory.

>[!note]- Section 2 — Helper functions
>
> Before the main math starts, the solver defines a few helper functions.
>
> For example:
>
> ```python
> def long_to_bytes(n):
>     if n == 0:
>         return b"\x00"
>     return n.to_bytes((n.bit_length() + 7) // 8, "big")
> ```
>
> This is needed because the original secret was turned into a large integer, so later we must convert candidate roots back into bytes.
>
> Another important helper is:
>
> ```python
> def modInverse(a, m):
>     return pow(a, -1, m)
> ```
>
> This computes modular inverses, which are required during:
>
> - Gaussian elimination modulo `p`
> - exponent reduction
> - modular root recovery
>
> The solver also includes Base64-related helpers:
>
> ```python
> def is_probably_base64(blob: bytes) -> bool:
> ...
>
> def peel_base64_all(blob: bytes):
> ...
> ```
>
> Their purpose is not to magically recover the final plaintext, but to help inspect whether a recovered candidate still looks like nested Base64.

>[!note]- Section 3 — Recovering the hidden polynomial
>
> The first real solve stage is recovering the original polynomial from the noisy shares.
>
> The solver uses random sampling:
>
> ```python
> for attempt in range(10000):
>     subset = random.sample(shares, k)
>     cur = get_coeffs(subset, k, p)
>     if cur is None:
>         continue
> ```
>
> Since `k = 15`, the script samples `15` shares at a time.
>
> This makes sense because a degree-`14` polynomial is uniquely determined by `15` valid points.
>
> So the idea here is simple:
>
> - randomly guess a subset of 15 shares
> - try to reconstruct a polynomial from them
> - hope that this subset contains enough honest points to reveal the real polynomial

>[!note]- Section 4 — Solving polynomial coefficients with Gaussian elimination
>
> Once a subset is chosen, the solver builds a linear system from those points:
>
> ```python
> def get_coeffs(subset, k, p):
>     mat = []
>     vec = []
>     for x, y in subset:
>         row = [pow(x, i, p) for i in range(k)]
>         mat.append(row)
>         vec.append(y % p)
>     return gaussian_elimination(mat, vec, p)
> ```
>
> This corresponds to solving the coefficients of:
>
> $$
> f(x) = c_0 + c_1x + c_2x^2 + \cdots + c_{14}x^{14} \pmod p
> $$
>
> Each share `(x, y)` gives one equation of that form.
>
> So the solver uses modular Gaussian elimination to recover the coefficients of a candidate polynomial.

>[!note]- Section 5 — Filtering out the fake shares
>
> Because the dataset contains fake points, not every polynomial reconstructed from a random subset is correct.
>
> So the solver verifies each candidate polynomial against **all** shares:
>
> ```python
> count = 0
> for x, y in shares:
>     if eval_poly(cur, x, p) == y % p:
>         count += 1
> ```
>
> Then it accepts the polynomial only if:
>
> ```python
> if count >= 31:
>     coeffs = cur
>     print(f"[+] Found valid polynomial! Passes through {count} points.")
>     break
> ```
>
> This threshold comes from the challenge structure:
>
> - total shares = `45`
> - fake shares = `14`
> - honest shares = `31`
>
> So a correct polynomial should pass through at least `31` points.
>
> In other words, this is the step where we identify the “honest witnesses” and ignore the liars.

>[!note]- Section 6 — Extracting the protected secret value
>
> Once the correct polynomial is found, the solver takes:
>
> ```python
> C = coeffs[0]
> ```
>
> This works because the challenge stored the secret in the constant term:
>
> $$
> c_0 = m^e \pmod p
> $$
>
> So after this step we recover:
>
> $$
> C = m^e \pmod p
> $$
>
> This is not the original flag yet.  
> It is the protected secret value that still needs to be “unlocked” by solving the modular root problem.

>[!note]- Section 7 — Reducing the huge exponent problem
>
> Directly solving:
>
> $$
> m^e \equiv C \pmod p
> $$
>
> would be impractical because `e` is huge.
>
> So the solver reduces the problem using group arithmetic modulo `p`:
>
> ```python
> e0 = e % (p - 1)
> d = gcd(e0, p - 1)
> k_red = e0 // d
> M = (p - 1) // d
> k_inv = modInverse(k_red, M)
> C_prime = pow(C, k_inv, p)
> ```
>
> This transforms the original equation into a smaller one:
>
> $$
> m^d \equiv C' \pmod p
> $$
>
> where:
>
> $$
> d = \gcd(e, p-1)
> $$
>
> In this challenge instance, that becomes:
>
> $$
> d = 70
> $$
>
> So instead of solving a gigantic `e`-th root, we only need to solve:
>
> $$
> m^{70} \equiv C' \pmod p
> $$

>[!note]- Section 8 — Breaking the 70-th root into smaller steps
>
> The solver uses the factorization:
>
> $$
> 70 = 7 \cdot 5 \cdot 2
> $$
>
> and solves the reduced root problem step by step:
>
> ```python
> r7 = nth_root_s1(C_prime, 7, p)
> r35 = nth_root_s1(r7, 5, p)
> r70 = square_root(r35, p)
> ```
>
> So the recovery chain is:
>
> 1. find one 7-th root
> 2. from that, find one 5-th root
> 3. from that, take a square root
>
> This gives one valid 70-th root.
>
> It is only one among many possible solutions, but it is enough as a starting point to generate all remaining candidates.

>[!note]- Section 9 — Generating all valid root candidates
>
> Once one 70-th root is found, the solver enumerates all possible solutions by multiplying it with all 70-th roots of unity:
>
> ```python
> roots_of_unity = get_all_70th_roots_of_unity(p)
> all_roots = [(r70 * u) % p for u in roots_of_unity]
> ```
>
> This works because if `r` is one solution of:
>
> $$
> x^{70} \equiv C' \pmod p
> $$
>
> then `r \cdot u` is also a solution whenever:
>
> $$
> u^{70} \equiv 1 \pmod p
> $$
>
> So this section enumerates all mathematically valid candidates for the original hidden integer `m`.

>[!note]- Section 10 — Converting candidates back into bytes
>
> At this point, each candidate is still just an integer.
>
> So the solver converts each one back into raw bytes:
>
> ```python
> raw = long_to_bytes(root)
> ```
>
> This reverses the original `bytes_to_long(flag)` transformation used by the challenge.
>
> After that, the candidate can be inspected as possible flag data.

>[!note]- Section 11 — Checking whether the candidate still looks Base64-wrapped
>
> Some candidates are not readable immediately.
>
> To inspect that, the solver tries to peel Base64 repeatedly:
>
> ```python
> chain = peel_base64_all(raw)
> final = chain[-1]
> ```
>
> The important detail here is:
>
> this step is mainly for **inspection**, not a guaranteed full plaintext recovery.
>
> It helps show whether the recovered candidate:
>
> - already looks like a flag
> - still looks Base64-encoded
> - or decodes into something more meaningful after one or more layers
>
> So this section helps us understand what the recovered root actually contains.

>[!note]- Section 12 — Ranking interesting candidates
>
> Because there may be many mathematically valid roots, the solver ranks candidates using a simple score:
>
> ```python
> score = candidate_score(raw, chain)
> ```
>
> A candidate gets a higher score if:
>
> - it contains `PETIR{`
> - it contains `PETIR`
> - it contains the word `flag`
> - its decoded output looks printable
> - its decoded output has brace-like structure
>
> This does not prove correctness mathematically.  
> It is just a practical way to push the most promising candidate to the bottom result section.

>[!note]- Section 13 — Identifying the correct wrapped flag
>
> After ranking the candidates, the solver prints the most interesting result in a clearer format.
>
> In this challenge, the solver correctly recovered a candidate with the expected outer structure:
>
> ```text
> PETIR{...}
> ```
>
> However, the inside was still Base64-encoded.
>
> So the important point is:
>
> the solver **did recover the correct root**, but the content inside the wrapper was still not the final readable plaintext.
>
> In other words, the solver gets us to the correct **wrapped flag**, not yet to the final human-readable message inside it.

>[!note]- Section 14 — Manual post-processing after the solver
>
> After the solver identified the correct wrapped candidate, the remaining Base64 layers were decoded manually.
>
> For example:
>
> ```bash
> echo "..." | base64 -d
> ```
>
> Repeating that step several times unwraps the remaining layers until the actual plaintext appears.
>
> So the readable string:
>
> ```text
> n01sy_p0lyn0m14ls_c4nt_h1d3_fr0m_b3rl3k4mp_67!
> ```
>
> was obtained **after** the solver finished, through manual decoding of the recovered wrapped content.
>
> This distinction matters:
>
> - the solver performs the heavy mathematical recovery
> - the final inner plaintext was obtained afterward by decoding the remaining Base64 layers manually

>[!note]- Section 15 — Final solve flow
>
> So the complete solve flow is:
>
> 1. read `p`, `k`, `e`, and the noisy shares
> 2. repeatedly sample 15 points and reconstruct candidate polynomials
> 3. keep the polynomial that matches at least 31 shares
> 4. extract the constant term `C = m^e mod p`
> 5. reduce the huge exponent problem into a 70-th root problem
> 6. solve one 70-th root via the `7 → 5 → 2` chain
> 7. generate all 70 candidate roots using roots of unity
> 8. convert those candidates back into bytes
> 9. identify the correct wrapped `PETIR{...}` candidate
> 10. manually decode the remaining Base64 layers
> 11. recover the final readable inner message
>
> So the main idea is:
>
> > first recover the true polynomial despite the noisy shares, then solve the modular root problem, then decode the wrapped result until the real message appears.
## FLAG

![[Pasted image 20260407084217.png]]

PETIR{n01sy_p0lyn0m14ls_c4nt_h1d3_fr0m_b3rl3k4mp_67!}