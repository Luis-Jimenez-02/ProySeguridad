import json

# Tus datos en formato JSON
data = '''
[
{"origen_texto":"POINT(21.90663577265221 -102.31478122193303)","destino_texto":"POINT(21.910175979498334 -102.31756511867034)"},
{"origen_texto":"POINT(21.90463173681414 -102.30710816066541)","destino_texto":"POINT(21.9099260596214 -102.31795605735944)"},
{"origen_texto":"POINT(21.909195012662973 -102.32130052408573)","destino_texto":"POINT(21.911264253884443 -102.32193572738181)"},
{"origen_texto":"POINT(21.913427390889293 -102.3149465619101)","destino_texto":"POINT(21.915866546562764 -102.31961053924674)"},
{"origen_texto":"POINT(21.909097637538064 -102.31722060084658)","destino_texto":"POINT(21.904297279580017 -102.3098299040973)"},
{"origen_texto":"POINT(21.91712167394211 -102.31692886358117)","destino_texto":"POINT(21.916459249539738 -102.30977921240894)"},
{"origen_texto":"POINT(21.906603703288997 -102.31535262705245)","destino_texto":"POINT(21.91538180308824 -102.3123126364449)"},
{"origen_texto":"POINT(21.907127935804162 -102.31712975324218)","destino_texto":"POINT(21.90595805325453 -102.30879804529954)"},
{"origen_texto":"POINT(21.91222892134506 -102.32371269794636)","destino_texto":"POINT(21.91178779936386 -102.30730284283385)"},
{"origen_texto":"POINT(21.912846227902424 -102.30646263015205)","destino_texto":"POINT(21.90887701672839 -102.32168952407636)"},
{"origen_texto":"POINT(21.909757662667072 -102.3242335698346)","destino_texto":"POINT(21.92072720924062 -102.30959712459578)"},
{"origen_texto":"POINT(21.91734732751792 -102.31398289322541)","destino_texto":"POINT(21.91781870737944 -102.31711303841662)"},
{"origen_texto":"POINT(21.915934581682624 -102.31661162394717)","destino_texto":"POINT(21.90990465998402 -102.30659802438218)"},
{"origen_texto":"POINT(21.912343556995182 -102.31906812977304)","destino_texto":"POINT(21.914449247609877 -102.32451939649071)"},
{"origen_texto":"POINT(21.921132098691693 -102.32342517483414)","destino_texto":"POINT(21.919724194040285 -102.31970181919132)"},
{"origen_texto":"POINT(21.907583020586575 -102.30989135198979)","destino_texto":"POINT(21.91172335447601 -102.31468994443918)"},
{"origen_texto":"POINT(21.91621601571582 -102.32101701523156)","destino_texto":"POINT(21.906003132290056 -102.31614781509585)"},
{"origen_texto":"POINT(21.91052853901102 -102.31327619109679)","destino_texto":"POINT(21.9180722734411 -102.30949381912127)"},
{"origen_texto":"POINT(21.90991866900405 -102.3237739683452)","destino_texto":"POINT(21.91748954564737 -102.31610969660987)"},
{"origen_texto":"POINT(21.912151185466833 -102.3093383119539)","destino_texto":"POINT(21.914600651659477 -102.31509789751301)"},
{"origen_texto":"POINT(21.913465809011978 -102.31155214330256)","destino_texto":"POINT(21.9188988924689 -102.32136066359756)"},
{"origen_texto":"POINT(21.920934803792992 -102.31245337510778)","destino_texto":"POINT(21.909221659357087 -102.30685722584349)"},
{"origen_texto":"POINT(21.920477390539656 -102.31098008348026)","destino_texto":"POINT(21.910998196259566 -102.31680178692383)"},
{"origen_texto":"POINT(21.90436324923434 -102.30562981592787)","destino_texto":"POINT(21.910057384066736 -102.31247602363662)"},
{"origen_texto":"POINT(21.91053399948485 -102.32403176882781)","destino_texto":"POINT(21.907074942553248 -102.3213018214144)"},
{"origen_texto":"POINT(21.90685030090182 -102.30646205578827)","destino_texto":"POINT(21.918721611497485 -102.32107918267073)"},
{"origen_texto":"POINT(21.905870747263094 -102.30959887067681)","destino_texto":"POINT(21.90398609344017 -102.3057411221988)"},
{"origen_texto":"POINT(21.91530463616996 -102.32472434870232)","destino_texto":"POINT(21.914506492446897 -102.32427015512258)"},
{"origen_texto":"POINT(21.903887576362482 -102.3092125601086)","destino_texto":"POINT(21.90686721660218 -102.3139511066915)"},
{"origen_texto":"POINT(21.914072056386367 -102.32212287674007)","destino_texto":"POINT(21.91102160918896 -102.30868017941786)"},
{"origen_texto":"POINT(21.913272375720286 -102.32089031468202)","destino_texto":"POINT(21.918996570616876 -102.30578594520959)"},
{"origen_texto":"POINT(21.921208042873097 -102.3095925461282)","destino_texto":"POINT(21.91297332067414 -102.31098046738586)"},
{"origen_texto":"POINT(21.90205959068651 -102.31483660679577)","destino_texto":"POINT(21.917866678055024 -102.30655861664582)"},
{"origen_texto":"POINT(21.910807499835833 -102.31626948362765)","destino_texto":"POINT(21.91244338790412 -102.31765911279348)"},
{"origen_texto":"POINT(21.907304865197705 -102.31830744361226)","destino_texto":"POINT(21.905789081045047 -102.31379818022283)"},
{"origen_texto":"POINT(21.90248142142582 -102.3202993230249)","destino_texto":"POINT(21.909630137967916 -102.31183421363124)"},
{"origen_texto":"POINT(21.911310054868363 -102.31537754688233)","destino_texto":"POINT(21.902890470694526 -102.31456387090255)"},
{"origen_texto":"POINT(21.919204362527303 -102.32285992687322)","destino_texto":"POINT(21.904108019144 -102.31828102634915)"},
{"origen_texto":"POINT(21.907965872254636 -102.31698209164502)","destino_texto":"POINT(21.901925350593388 -102.32210498717153)"},
{"origen_texto":"POINT(21.91479911826855 -102.32025552738594)","destino_texto":"POINT(21.90963437190809 -102.30783137557941)"},
{"origen_texto":"POINT(21.903741191891598 -102.32347558042277)","destino_texto":"POINT(21.90704287361521 -102.30696832616259)"},
{"origen_texto":"POINT(21.90842208319932 -102.3128361384081)","destino_texto":"POINT(21.912032099151965 -102.31656424106285)"},
{"origen_texto":"POINT(21.911355661379243 -102.31655269044899)","destino_texto":"POINT(21.903212471037428 -102.31983456836055)"},
{"origen_texto":"POINT(21.92039704649875 -102.32199930019469)","destino_texto":"POINT(21.91043857192786 -102.31914367103599)"},
{"origen_texto":"POINT(21.907134563937497 -102.30708275165752)","destino_texto":"POINT(21.917424814016726 -102.31283034327015)"},
{"origen_texto":"POINT(21.91312993651581 -102.30511495803991)","destino_texto":"POINT(21.909158342441224 -102.30986340888822)"},
{"origen_texto":"POINT(21.90325019643254 -102.31588927903921)","destino_texto":"POINT(21.91390250197707 -102.3187709453676)"},
{"origen_texto":"POINT(21.902063913806998 -102.32424101246961)","destino_texto":"POINT(21.91860028927714 -102.32389674871816)"},
{"origen_texto":"POINT(21.91623785159154 -102.31683924647238)","destino_texto":"POINT(21.904783126068153 -102.32115880729715)"},
{"origen_texto":"POINT(21.904544297547968 -102.30821265415888)","destino_texto":"POINT(21.90986765982048 -102.31835969668712)"},
{"origen_texto":"POINT(21.90385358477985 -102.32355098164659)","destino_texto":"POINT(21.9065873243432 -102.32120833685562)"},
{"origen_texto":"POINT(21.903145783148968 -102.32415495055017)","destino_texto":"POINT(21.912265795703576 -102.30879225441763)"},
{"origen_texto":"POINT(21.917506006398995 -102.32334601068591)","destino_texto":"POINT(21.911168380060143 -102.32083302055555)"},
{"origen_texto":"POINT(21.906077881246425 -102.32300028224395)","destino_texto":"POINT(21.92098858380361 -102.31036192608616)"},
{"origen_texto":"POINT(21.915360330873646 -102.30934707146187)","destino_texto":"POINT(21.920468349716838 -102.31112269170373)"},
{"origen_texto":"POINT(21.914191334406127 -102.31470355939572)","destino_texto":"POINT(21.90714403990858 -102.31173581753853)"},
{"origen_texto":"POINT(21.914541298957158 -102.30698228934595)","destino_texto":"POINT(21.910286717517742 -102.31260838157043)"},
{"origen_texto":"POINT(21.91532902248572 -102.31490978534922)","destino_texto":"POINT(21.91953210608443 -102.31763872842569)"},
{"origen_texto":"POINT(21.91915341954689 -102.30675855688006)","destino_texto":"POINT(21.90297426567083 -102.31531395006765)"},
{"origen_texto":"POINT(21.918964218789693 -102.31264222501841)","destino_texto":"POINT(21.907345590056632 -102.32019492342218)"},
{"origen_texto":"POINT(21.906547434506585 -102.31047107263336)","destino_texto":"POINT(21.904931247730357 -102.31079882799797)"},
{"origen_texto":"POINT(21.915561286186616 -102.31220297206339)","destino_texto":"POINT(21.92071744774354 -102.30737082736597)"},
{"origen_texto":"POINT(21.913132485997064 -102.31936157208297)","destino_texto":"POINT(21.906791540818965 -102.31037280107061)"},
{"origen_texto":"POINT(21.909379255687856 -102.32283296296474)","destino_texto":"POINT(21.907077782765256 -102.31655276329197)"},
{"origen_texto":"POINT(21.920918816990476 -102.31915009510999)","destino_texto":"POINT(21.90752470112156 -102.31050720191476)"},
{"origen_texto":"POINT(21.919967235155394 -102.30696843916729)","destino_texto":"POINT(21.91839614805575 -102.30705490839792)"},
{"origen_texto":"POINT(21.904813504429924 -102.31409319566288)","destino_texto":"POINT(21.915715496664507 -102.3242732734989)"},
{"origen_texto":"POINT(21.90894267798594 -102.32120532297287)","destino_texto":"POINT(21.91670710262152 -102.32112393458141)"},
{"origen_texto":"POINT(21.90970552241191 -102.31819727331244)","destino_texto":"POINT(21.91054929412183 -102.30675541705256)"},
{"origen_texto":"POINT(21.91247229085983 -102.31613219129368)","destino_texto":"POINT(21.91969492680141 -102.3179467170533)"},
{"origen_texto":"POINT(21.906914023270076 -102.30745067882896)","destino_texto":"POINT(21.920681935196328 -102.32254885725413)"},
{"origen_texto":"POINT(21.907099492018528 -102.32078448118413)","destino_texto":"POINT(21.912609946426716 -102.3071582121362)"},
{"origen_texto":"POINT(21.9201533562736 -102.32214125819849)","destino_texto":"POINT(21.921108681557996 -102.31262036115547)"},
{"origen_texto":"POINT(21.915237022319307 -102.30535394108776)","destino_texto":"POINT(21.902287578911196 -102.31003505937265)"},
{"origen_texto":"POINT(21.915622056264922 -102.30646632929071)","destino_texto":"POINT(21.916605702634953 -102.32044987307879)"},
{"origen_texto":"POINT(21.9177889856827 -102.31669881554559)","destino_texto":"POINT(21.90716972238543 -102.30548310935814)"},
{"origen_texto":"POINT(21.915353508997544 -102.30622631803652)","destino_texto":"POINT(21.913683640871593 -102.32447240344217)"},
{"origen_texto":"POINT(21.92126829601688 -102.31948191568321)","destino_texto":"POINT(21.907798698837297 -102.31982772128264)"},
{"origen_texto":"POINT(21.920411859543652 -102.31060783098928)","destino_texto":"POINT(21.918745314638844 -102.30980092573814)"},
{"origen_texto":"POINT(21.9127653783499 -102.31719515648128)","destino_texto":"POINT(21.90546043656109 -102.31795452357844)"},
{"origen_texto":"POINT(21.920623294198492 -102.31092816885123)","destino_texto":"POINT(21.905855129693087 -102.32338106790903)"},
{"origen_texto":"POINT(21.914173843213508 -102.31776443730077)","destino_texto":"POINT(21.91094104197741 -102.30706505020602)"},
{"origen_texto":"POINT(21.920287094072552 -102.31730925406706)","destino_texto":"POINT(21.90648750015183 -102.3185845330424)"},
{"origen_texto":"POINT(21.915140287293912 -102.30664381290487)","destino_texto":"POINT(21.90148836695957 -102.32005749563801)"},
{"origen_texto":"POINT(21.9121268814268 -102.30565522524364)","destino_texto":"POINT(21.91235476711401 -102.30499318713531)"},
{"origen_texto":"POINT(21.91669125268156 -102.3167361887829)","destino_texto":"POINT(21.907363775262926 -102.31914344782636)"},
{"origen_texto":"POINT(21.90632089286413 -102.32187288813961)","destino_texto":"POINT(21.920774549087035 -102.3219324235084)"},
{"origen_texto":"POINT(21.90223314068102 -102.30742839086048)","destino_texto":"POINT(21.91405583468528 -102.31681746513638)"},
{"origen_texto":"POINT(21.918242867210807 -102.309775264483)","destino_texto":"POINT(21.918307240716214 -102.30712558567397)"},
{"origen_texto":"POINT(21.915691304633487 -102.31136740656062)","destino_texto":"POINT(21.903740199570862 -102.321029081747)"},
{"origen_texto":"POINT(21.916748018239062 -102.31281875603626)","destino_texto":"POINT(21.913779656169666 -102.3217814703408)"},
{"origen_texto":"POINT(21.90943172193375 -102.30909371956065)","destino_texto":"POINT(21.919440439630893 -102.31736399597025)"},
{"origen_texto":"POINT(21.919823189612273 -102.30592486651318)","destino_texto":"POINT(21.910372994169702 -102.31775579916847)"},
{"origen_texto":"POINT(21.909201976835377 -102.30517347220275)","destino_texto":"POINT(21.908332296211178 -102.31427752329132)"},
{"origen_texto":"POINT(21.91029440974182 -102.3056756548486)","destino_texto":"POINT(21.915972867006957 -102.31803108988817)"},
{"origen_texto":"POINT(21.916737626825388 -102.31524080698085)","destino_texto":"POINT(21.904263418918276 -102.32263991147097)"},
{"origen_texto":"POINT(21.90276005110697 -102.30702437444829)","destino_texto":"POINT(21.908658380365903 -102.31772003128685)"},
{"origen_texto":"POINT(21.90976682286845 -102.31125821525407)","destino_texto":"POINT(21.908375035126788 -102.32333038992509)"},
{"origen_texto":"POINT(21.920507922484106 -102.30600649576225)","destino_texto":"POINT(21.903113328332687 -102.32105634205442)"},
{"origen_texto":"POINT(21.912025098119383 -102.30631389657158)","destino_texto":"POINT(21.90700106598172 -102.32341914268784)"},
{"origen_texto":"POINT(21.91082188777612 -102.31335719998025)","destino_texto":"POINT(21.910045510602576 -102.30943766898939)"},
{"origen_texto":"POINT(21.913632249798603 -102.30902037544804)","destino_texto":"POINT(21.911136279714174 -102.3207966627)"},
{"origen_texto":"POINT(21.9074972310905 -102.31599698167446)","destino_texto":"POINT(21.901912915461626 -102.32234878129233)"},
{"origen_texto":"POINT(21.90982439450021 -102.31032832890156)","destino_texto":"POINT(21.901861051963724 -102.30965578360633)"},
{"origen_texto":"POINT(21.907633285461095 -102.31227661690383)","destino_texto":"POINT(21.91377247525029 -102.30723518220069)"},
{"origen_texto":"POINT(21.90605975829291 -102.3153393427865)","destino_texto":"POINT(21.91367326058595 -102.32364237052921)"},
{"origen_texto":"POINT(21.90694473584294 -102.3060941940911)","destino_texto":"POINT(21.90438086668994 -102.30697359749993)"},
{"origen_texto":"POINT(21.916508808466094 -102.31841609890732)","destino_texto":"POINT(21.90818899810574 -102.31243500367194)"},
{"origen_texto":"POINT(21.91739757124728 -102.3122595639512)","destino_texto":"POINT(21.904869052574334 -102.32490250899093)"},
{"origen_texto":"POINT(21.910155088580428 -102.30667819582412)","destino_texto":"POINT(21.90642506985266 -102.31388422580616)"},
{"origen_texto":"POINT(21.916688948667037 -102.30677134094218)","destino_texto":"POINT(21.905490764914937 -102.32224348663085)"},
{"origen_texto":"POINT(21.903506083773532 -102.31073560339507)","destino_texto":"POINT(21.90740752257171 -102.3221610529886)"},
{"origen_texto":"POINT(21.91329339603547 -102.31232121528016)","destino_texto":"POINT(21.90280030980466 -102.30546912903773)"},
{"origen_texto":"POINT(21.91144615926969 -102.32412518344702)","destino_texto":"POINT(21.9157845051781 -102.32148172434667)"},
{"origen_texto":"POINT(21.911249476199547 -102.30950214006663)","destino_texto":"POINT(21.910729177108045 -102.31952029832603)"},
{"origen_texto":"POINT(21.90635807756262 -102.32322907913333)","destino_texto":"POINT(21.902257782250064 -102.31306441823295)"},
{"origen_texto":"POINT(21.901866010384694 -102.31138629018595)","destino_texto":"POINT(21.91987348542437 -102.31509429417817)"},
{"origen_texto":"POINT(21.912671886702977 -102.30671981557995)","destino_texto":"POINT(21.914253360165567 -102.31068276445792)"},
{"origen_texto":"POINT(21.91952268183256 -102.32138757710929)","destino_texto":"POINT(21.9183770788571 -102.30799106906157)"},
{"origen_texto":"POINT(21.906530313139385 -102.31718471744445)","destino_texto":"POINT(21.916180694051157 -102.31256504251368)"},
{"origen_texto":"POINT(21.906707387982152 -102.31245544627956)","destino_texto":"POINT(21.91422910260275 -102.31680186322629)"},
{"origen_texto":"POINT(21.910275117262866 -102.32243548921207)","destino_texto":"POINT(21.916448464498362 -102.31413215202339)"},
{"origen_texto":"POINT(21.908723372709872 -102.32460515140768)","destino_texto":"POINT(21.909643633809075 -102.30633161783025)"},
{"origen_texto":"POINT(21.905333762625872 -102.3126534731644)","destino_texto":"POINT(21.913728738046995 -102.31281753356207)"},
{"origen_texto":"POINT(21.915073362921955 -102.32347069835538)","destino_texto":"POINT(21.914446163941506 -102.32099225910792)"},
{"origen_texto":"POINT(21.903753371147282 -102.30772209770129)","destino_texto":"POINT(21.901597781588013 -102.32437569119479)"},
{"origen_texto":"POINT(21.907326499351473 -102.31197815502573)","destino_texto":"POINT(21.921205040858972 -102.31222257906562)"},
{"origen_texto":"POINT(21.903587636315063 -102.30989002936691)","destino_texto":"POINT(21.91483443621395 -102.31560420218868)"},
{"origen_texto":"POINT(21.911722823996694 -102.31454468588666)","destino_texto":"POINT(21.906416791408585 -102.31511630543694)"},
{"origen_texto":"POINT(21.915328706415814 -102.3109987237055)","destino_texto":"POINT(21.912837460770792 -102.31812182963813)"},
{"origen_texto":"POINT(21.90944279398456 -102.31827367720453)","destino_texto":"POINT(21.916881846231497 -102.32458322977634)"},
{"origen_texto":"POINT(21.911023582964585 -102.32442419066908)","destino_texto":"POINT(21.903860570359907 -102.30941544730462)"},
{"origen_texto":"POINT(21.914710455097826 -102.30611450827067)","destino_texto":"POINT(21.912539911915317 -102.30958514185032)"},
{"origen_texto":"POINT(21.916638649130714 -102.31778550970701)","destino_texto":"POINT(21.91849331807316 -102.31643283267968)"},
{"origen_texto":"POINT(21.91468192612534 -102.31421667060555)","destino_texto":"POINT(21.90437113820829 -102.32282608224327)"},
{"origen_texto":"POINT(21.905277623443794 -102.32416916075063)","destino_texto":"POINT(21.90789325472982 -102.31597958311875)"},
{"origen_texto":"POINT(21.910258594569967 -102.31998026646346)","destino_texto":"POINT(21.901778561692016 -102.31582712935517)"},
{"origen_texto":"POINT(21.902656585461237 -102.30857915634982)","destino_texto":"POINT(21.90730259902058 -102.3098084351586)"},
{"origen_texto":"POINT(21.91761073907961 -102.31250692976238)","destino_texto":"POINT(21.913475377083987 -102.32048437533652)"},
{"origen_texto":"POINT(21.918168578203108 -102.31896337214624)","destino_texto":"POINT(21.91561375243395 -102.30584689579462)"},
{"origen_texto":"POINT(21.90546579495281 -102.30797079241353)","destino_texto":"POINT(21.911949553003108 -102.31483318371039)"},
{"origen_texto":"POINT(21.90145033625454 -102.3122102992662)","destino_texto":"POINT(21.917662112726674 -102.30522618696253)"},
{"origen_texto":"POINT(21.915940814477157 -102.32001841408206)","destino_texto":"POINT(21.901705636363115 -102.31716041382924)"},
{"origen_texto":"POINT(21.910549092037943 -102.3203021987935)","destino_texto":"POINT(21.91507751606406 -102.31593255943336)"},
{"origen_texto":"POINT(21.919979694222036 -102.3194700614827)","destino_texto":"POINT(21.911143400993613 -102.31858513120802)"},
{"origen_texto":"POINT(21.917271367414855 -102.31533193391103)","destino_texto":"POINT(21.910781346668227 -102.3233103709575)"},
{"origen_texto":"POINT(21.902730214936554 -102.32279414556402)","destino_texto":"POINT(21.904362800421833 -102.31638764736368)"},
{"origen_texto":"POINT(21.90549534379573 -102.31144907868806)","destino_texto":"POINT(21.90739569682993 -102.31792880431905)"},
{"origen_texto":"POINT(21.914412323865378 -102.31525102401004)","destino_texto":"POINT(21.905022431160738 -102.30792667566877)"},
{"origen_texto":"POINT(21.906851273369515 -102.32473984288168)","destino_texto":"POINT(21.919051402813373 -102.30633882166599)"},
{"origen_texto":"POINT(21.913278779531236 -102.32340713468918)","destino_texto":"POINT(21.909040334375955 -102.3125271036768)"},
{"origen_texto":"POINT(21.914316515918784 -102.31035180469266)","destino_texto":"POINT(21.902185888806457 -102.32316781750961)"},
{"origen_texto":"POINT(21.916603295852905 -102.30890641553282)","destino_texto":"POINT(21.919354991198507 -102.32109322766539)"},
{"origen_texto":"POINT(21.919672197877713 -102.31086647851507)","destino_texto":"POINT(21.91401787700552 -102.30614988798686)"},
{"origen_texto":"POINT(21.912609802789742 -102.30833524053084)","destino_texto":"POINT(21.911086366298562 -102.31233278101526)"},
{"origen_texto":"POINT(21.912868627320687 -102.31217733931351)","destino_texto":"POINT(21.90366528041315 -102.30721661187651)"},
{"origen_texto":"POINT(21.919122760214716 -102.31027147170171)","destino_texto":"POINT(21.9086807711349 -102.32128213363042)"},
{"origen_texto":"POINT(21.90545156721974 -102.3144449477271)","destino_texto":"POINT(21.909467943064158 -102.3055340885645)"},
{"origen_texto":"POINT(21.91865265458942 -102.32040714266556)","destino_texto":"POINT(21.920050861490076 -102.31418456205559)"},
{"origen_texto":"POINT(21.912813293835296 -102.31772859929346)","destino_texto":"POINT(21.903217506247717 -102.31724527993593)"},
{"origen_texto":"POINT(21.91702197641011 -102.31979558417409)","destino_texto":"POINT(21.91727958248037 -102.31532832379705)"},
{"origen_texto":"POINT(21.90559343370977 -102.3213022446436)","destino_texto":"POINT(21.914908412654313 -102.31306964151526)"},
{"origen_texto":"POINT(21.90302441554481 -102.32289220451673)","destino_texto":"POINT(21.911524124875257 -102.31355357142242)"},
{"origen_texto":"POINT(21.912511085735694 -102.31068445104776)","destino_texto":"POINT(21.90457095081046 -102.3181799166586)"},
{"origen_texto":"POINT(21.917847502096787 -102.31912731930848)","destino_texto":"POINT(21.904451515277852 -102.3092186619339)"},
{"origen_texto":"POINT(21.908557737363044 -102.30909713032995)","destino_texto":"POINT(21.917410861458222 -102.31252969434776)"},
{"origen_texto":"POINT(21.916258866410395 -102.32068767985453)","destino_texto":"POINT(21.906730341671068 -102.30718689539705)"},
{"origen_texto":"POINT(21.913610012785632 -102.30563721603653)","destino_texto":"POINT(21.90391188084172 -102.3228377859772)"},
{"origen_texto":"POINT(21.90167304461497 -102.31431642808782)","destino_texto":"POINT(21.91103718423779 -102.32114509821001)"},
{"origen_texto":"POINT(21.914545199677743 -102.31123608250522)","destino_texto":"POINT(21.911005719306573 -102.30956807577299)"},
{"origen_texto":"POINT(21.9115754867145 -102.32023923262273)","destino_texto":"POINT(21.92082815199777 -102.30955221815051)"},
{"origen_texto":"POINT(21.908675158901183 -102.31158202916048)","destino_texto":"POINT(21.91369694593982 -102.31598999287522)"},
{"origen_texto":"POINT(21.903820978502846 -102.31500091129833)","destino_texto":"POINT(21.91560876511183 -102.31952174193923)"},
{"origen_texto":"POINT(21.919755301052955 -102.32481026844093)","destino_texto":"POINT(21.90734753151812 -102.3242396407421)"},
{"origen_texto":"POINT(21.914892845842903 -102.31779939030017)","destino_texto":"POINT(21.912925747932515 -102.30556471813426)"},
{"origen_texto":"POINT(21.91717364693032 -102.31187224196323)","destino_texto":"POINT(21.90550072471514 -102.32431140629537)"},
{"origen_texto":"POINT(21.914737682654902 -102.30577246077333)","destino_texto":"POINT(21.912359114438885 -102.31087698617334)"},
{"origen_texto":"POINT(21.910038016932347 -102.31326655754438)","destino_texto":"POINT(21.90900121992265 -102.32144296509125)"},
{"origen_texto":"POINT(21.916277626270006 -102.32176930245124)","destino_texto":"POINT(21.90905667624545 -102.30612190975067)"},
{"origen_texto":"POINT(21.916137157011644 -102.32374794697276)","destino_texto":"POINT(21.907173030089307 -102.3243083058197)"},
{"origen_texto":"POINT(21.90730292634608 -102.31505805255323)","destino_texto":"POINT(21.918213088091495 -102.32402732316766)"},
{"origen_texto":"POINT(21.916304159684667 -102.30507143834005)","destino_texto":"POINT(21.91665961597917 -102.31828781302119)"},
{"origen_texto":"POINT(21.907107128438156 -102.30511654543814)","destino_texto":"POINT(21.904685134586366 -102.31572449517128)"},
{"origen_texto":"POINT(21.914757011000265 -102.30619874660391)","destino_texto":"POINT(21.903255601588132 -102.31976653056805)"},
{"origen_texto":"POINT(21.914317980944105 -102.31045515665124)","destino_texto":"POINT(21.90718699688091 -102.31828404441318)"},
{"origen_texto":"POINT(21.905895205402096 -102.32170858346258)","destino_texto":"POINT(21.920603859835605 -102.3204258435774)"},
{"origen_texto":"POINT(21.91328586318422 -102.30869965981861)","destino_texto":"POINT(21.918638344790274 -102.31776458423877)"},
{"origen_texto":"POINT(21.917599720446212 -102.31646266581997)","destino_texto":"POINT(21.919618120394148 -102.3111349209464)"},
{"origen_texto":"POINT(21.921339983019394 -102.30633767139152)","destino_texto":"POINT(21.902586118882596 -102.31828339745111)"},
{"origen_texto":"POINT(21.909904338272174 -102.31746675089553)","destino_texto":"POINT(21.915441749300637 -102.32290112077966)"},
{"origen_texto":"POINT(21.91379032321569 -102.31312877999548)","destino_texto":"POINT(21.9210011148076 -102.31699785773094)"},
{"origen_texto":"POINT(21.91836114027522 -102.32293800251438)","destino_texto":"POINT(21.915773225586427 -102.31607272374984)"},
{"origen_texto":"POINT(21.902850662715437 -102.32093374463567)","destino_texto":"POINT(21.904913691058933 -102.30876751678016)"},
{"origen_texto":"POINT(21.907834864829113 -102.31995296524748)","destino_texto":"POINT(21.920069491925464 -102.31157006088422)"},
{"origen_texto":"POINT(21.913495306517426 -102.31869855480421)","destino_texto":"POINT(21.906578161167594 -102.32461067150984)"},
{"origen_texto":"POINT(21.914698282127308 -102.31279254427956)","destino_texto":"POINT(21.919362314844346 -102.3212984566411)"},
{"origen_texto":"POINT(21.914449066736726 -102.31759698668333)","destino_texto":"POINT(21.90328785623336 -102.32220255545415)"},
{"origen_texto":"POINT(21.917721320017527 -102.32333696252104)","destino_texto":"POINT(21.904811370348018 -102.31313993172708)"},
{"origen_texto":"POINT(21.912715579161596 -102.31552386612616)","destino_texto":"POINT(21.91608024258743 -102.32477726993828)"},
{"origen_texto":"POINT(21.90861247150262 -102.31530659587763)","destino_texto":"POINT(21.91108149814137 -102.31525973341445)"},
{"origen_texto":"POINT(21.91389364519493 -102.31925534690298)","destino_texto":"POINT(21.911431879569648 -102.31574532526552)"},
{"origen_texto":"POINT(21.90160768772271 -102.3118422537189)","destino_texto":"POINT(21.908292699110884 -102.31159009614)"},
{"origen_texto":"POINT(21.91410943556296 -102.32115563543334)","destino_texto":"POINT(21.908141326108055 -102.30783370828094)"},
{"origen_texto":"POINT(21.91867384703589 -102.32049698310219)","destino_texto":"POINT(21.914539697206347 -102.32381573440225)"},
{"origen_texto":"POINT(21.91463284071402 -102.31726605082302)","destino_texto":"POINT(21.90470925427821 -102.31736162939742)"},
{"origen_texto":"POINT(21.91299964446298 -102.31914290072069)","destino_texto":"POINT(21.90514756606179 -102.32456461683935)"},
{"origen_texto":"POINT(21.902475266904936 -102.31810288216117)","destino_texto":"POINT(21.90834976825693 -102.3061512786574)"},
{"origen_texto":"POINT(21.913385450767137 -102.32282700000846)","destino_texto":"POINT(21.907090651644996 -102.31487949733335)"},
{"origen_texto":"POINT(21.92002667941384 -102.31157514366866)","destino_texto":"POINT(21.908533717810304 -102.31707710462882)"},
{"origen_texto":"POINT(21.916041314625787 -102.32124776053756)","destino_texto":"POINT(21.91619184771535 -102.32164594322435)"},
{"origen_texto":"POINT(21.909353506858707 -102.31155476847738)","destino_texto":"POINT(21.912865160373045 -102.31174368714045)"},
{"origen_texto":"POINT(21.91280746549406 -102.31415143705846)","destino_texto":"POINT(21.916165248033003 -102.31005309243044)"},
{"origen_texto":"POINT(21.92091706267889 -102.31261165834752)","destino_texto":"POINT(21.912787246515837 -102.30572412926713)"},
{"origen_texto":"POINT(21.91972179337518 -102.31912199403874)","destino_texto":"POINT(21.916478703172732 -102.3109512626729)"},
{"origen_texto":"POINT(21.92077560047267 -102.31338813911827)","destino_texto":"POINT(21.910872739185674 -102.30822063093412)"},
{"origen_texto":"POINT(21.91251652275491 -102.30856619702851)","destino_texto":"POINT(21.909802627141072 -102.31210160460085)"},
{"origen_texto":"POINT(21.911888730234296 -102.31315372423427)","destino_texto":"POINT(21.909686347253977 -102.31814438607118)"},
{"origen_texto":"POINT(21.920309441232078 -102.32018537977476)","destino_texto":"POINT(21.906773535180314 -102.31247602322536)"},
{"origen_texto":"POINT(21.920851650677694 -102.3091941292075)","destino_texto":"POINT(21.91423100010173 -102.30830741770738)"},
{"origen_texto":"POINT(21.911807309998583 -102.31862846462862)","destino_texto":"POINT(21.908030934849553 -102.3137146946598)"},
{"origen_texto":"POINT(21.910671861196747 -102.31372142450422)","destino_texto":"POINT(21.9194064784458 -102.32270417032404)"},
{"origen_texto":"POINT(21.920547917202995 -102.30670924528232)","destino_texto":"POINT(21.901607846608762 -102.31991300102757)"},
{"origen_texto":"POINT(21.904225588091307 -102.32012068523284)","destino_texto":"POINT(21.915909462963313 -102.30971405003073)"},
{"origen_texto":"POINT(21.91513348332306 -102.31007432657113)","destino_texto":"POINT(21.906219605791136 -102.31967956252278)"},
{"origen_texto":"POINT(21.901720776247654 -102.31568792876604)","destino_texto":"POINT(21.91708768771933 -102.318171188544)"},
{"origen_texto":"POINT(21.906901311199547 -102.30677382300256)","destino_texto":"POINT(21.914353045063645 -102.31077033773671)"},
{"origen_texto":"POINT(21.9026050910037 -102.31471442711407)","destino_texto":"POINT(21.918533072749266 -102.31394847485709)"},
{"origen_texto":"POINT(21.90668644890047 -102.32174157565692)","destino_texto":"POINT(21.909849936342894 -102.3122755373309)"},
{"origen_texto":"POINT(21.915708968718498 -102.31307492291043)","destino_texto":"POINT(21.910631084132305 -102.31215589980319)"},
{"origen_texto":"POINT(21.913332813631886 -102.3147247081308)","destino_texto":"POINT(21.89434769743571 -102.32272157108191)"},
{"origen_texto":"POINT(21.913332813631886 -102.3147247081308)","destino_texto":"POINT(21.899153554908356 -102.30911416991762)"},
{"origen_texto":"POINT(21.913332813631886 -102.3147247081308)","destino_texto":"POINT(21.912489077086068 -102.27842119210243)"},
{"origen_texto":"POINT(21.913332813631886 -102.3147247081308)","destino_texto":"POINT(21.923844034756012 -102.28111363109382)"},
{"origen_texto":"POINT(21.913332813631886 -102.3147247081308)","destino_texto":"POINT(21.895464141825986 -102.28558719381708)"},
{"origen_texto":"POINT(21.913332813631886 -102.3147247081308)","destino_texto":"POINT(21.887760258247386 -102.28481603995235)"},
{"origen_texto":"POINT(21.913332813631886 -102.3147247081308)","destino_texto":"POINT(21.878531464834712 -102.28576013612394)"},
{"origen_texto":"POINT(21.913332813631886 -102.3147247081308)","destino_texto":"POINT(21.872480065422202 -102.32615618680948)"},
{"origen_texto":"POINT(21.913332813631886 -102.3147247081308)","destino_texto":"POINT(21.85755856219808 -102.30115387424301)"},
{"origen_texto":"POINT(21.82265148605994 -102.27349144533447)","destino_texto":"POINT(21.913332813631886 -102.3147247081308)"},
{"origen_texto":"POINT(21.867733201452396 -102.30563457192532)","destino_texto":"POINT(21.913332813631886 -102.3147247081308)"},
{"origen_texto":"POINT(21.88132709704727 -102.30566261251855)","destino_texto":"POINT(21.913332813631886 -102.3147247081308)"},
{"origen_texto":"POINT(21.898129476526446 -102.29757930824451)","destino_texto":"POINT(21.913332813631886 -102.3147247081308)"},
{"origen_texto":"POINT(21.900840702662794 -102.29834461625491)","destino_texto":"POINT(21.913332813631886 -102.3147247081308)"},
{"origen_texto":"POINT(21.900528735082926 -102.2936801669358)","destino_texto":"POINT(21.913332813631886 -102.3147247081308)"}
]
'''

# Convertir el JSON a objetos Python
datos = json.loads(data)

# Nombre del archivo de salida
nombre_archivo = "datos_geolocalizacion.txt"

# Abrir el archivo en modo escritura
with open(nombre_archivo, "w") as archivo:
    # Formatear los datos y escribir en el archivo
    for dato in datos:
        origen_lat_lon = dato["origen_texto"].replace("POINT(", "").replace(")", "").split()
        destino_lat_lon = dato["destino_texto"].replace("POINT(", "").replace(")", "").split()

        archivo.write('{"index": {"_index": "geolocalizacion"}}\n')
        archivo.write('{"origen": {"lat": ' + origen_lat_lon[0] + ', "lon": ' + origen_lat_lon[1] + '}, "destino": {"lat": ' + destino_lat_lon[0] + ', "lon": ' + destino_lat_lon[1] + '}}\n')

print(f"Los datos han sido guardados en el archivo: {nombre_archivo}")
